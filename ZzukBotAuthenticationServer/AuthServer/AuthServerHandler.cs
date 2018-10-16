using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZzukBotAuthenticationServer.AuthServer.Users;
using ZzukBotAuthenticationServer.Models;
#pragma warning disable 4014

namespace ZzukBotAuthenticationServer.AuthServer
{
    internal class AuthServerHandler
    {
        private static readonly object _lock = new object();
        private static readonly Lazy<AuthServerHandler> _instance = new Lazy<AuthServerHandler>(() => new AuthServerHandler());
        internal static AuthServerHandler Instance
        {
            get
            {
                lock (_lock)
                {
                    return _instance.Value;
                }
            }
        }
        private AuthServerHandler()
        {
        }

        private TcpListener _listener;
        private int _waitingSockets;
        private int _activeConnectionCount;
        internal static event EventHandler<PacketModel> OnClientPing;
        internal static event EventHandler OnClientDisconnect;

        // ReSharper disable once ClassNeverInstantiated.Local
        private class Connection
        {
            internal string HadwareId { get; set; }
            internal string Ip { get; set; }
            internal Client RelatedConnection { get; set; }
        }
        private readonly ConcurrentDictionary<string, HashSet<Connection>> _activeConnections =
            new ConcurrentDictionary<string, HashSet<Connection>>();

        internal void StartAuth()
        {
            _listener = new TcpListener(AuthData.Instance.IpAddress, AuthData.Instance.Port);
            _listener.Start();
            ConnectionAccepter();
        }
        private void ConnectionAccepter()
        {
            while (true)
            {
                if (_waitingSockets < AuthData.Instance.MaxWaitingSockets - 1 &&
                    _activeConnectionCount <= AuthData.Instance.MaxClients)
                {
                    HandleConnection();
                }
                else
                {
                    Thread.Sleep(50);
                }
            }
        }
        private async void HandleConnection()
        {
            var waitingIncremented = false;
            try
            {
                using (var task = _listener.AcceptTcpClientAsync())
                {
                    Interlocked.Increment(ref _waitingSockets);
                    waitingIncremented = true;
                    Interlocked.Increment(ref _activeConnectionCount);
                    await task;
                    Interlocked.Decrement(ref _waitingSockets);
                    waitingIncremented = false;
                    if (task.IsCanceled || task.IsFaulted || !task.IsCompleted)
                    {
                        Interlocked.Decrement(ref _activeConnectionCount);
                        return;
                    }
                    var client = new Client(task.Result, OnClientClose);
                    Task.Run(() =>
                    {
                        ProcessClient(client);
                        client.CloseConnection();
                    });
                }
            }
            catch (Exception e)
            {
                if (waitingIncremented)
                    Interlocked.Decrement(ref _waitingSockets);
            }
        }

        private void OnClientClose(Client client)
        {
            Interlocked.Decrement(ref _activeConnectionCount);
            OnClientDisconnect?.Invoke(client, EventArgs.Empty);
        }

        private void ProcessClient(Client client)
        {
            HashSet<Connection> userActiveConnections = null;
            Connection con = null;
            UserInfo user = null;
            try
            {
                // Get Ping packet
                var packet = client.GetNextPacket();
                if (packet.Opcode != (uint) Opcodes.Ping)
                {
                    return;
                }
                // Send Pong packet
                client.Write((uint) Opcodes.Pong);

                // Recieve acc name and pass
                var packets = client.GetRandomly(10, (uint) Opcodes.AccountName, (uint) Opcodes.AccountPassword);
                var accountName = packets[0]?.Content.BToString().ToLower();
                var accountPass = packets[1]?.Content.BToString();
                if (string.IsNullOrWhiteSpace(accountName) || string.IsNullOrWhiteSpace(accountPass))
                {
                    client.CloseConnection();
                    return;
                }
                user = Manager.GetUserDetails(accountName, accountPass);
                if (user == null)
                {
                    // Invalid account data
                    client.Write((uint) Opcodes.LoginResult, new byte[] {2});
                    return;
                }
                // Login successful
                client.Write((uint) Opcodes.LoginResult, new byte[] {1});

                if (!_activeConnections.TryGetValue(accountName, out userActiveConnections))
                {
                    userActiveConnections = new HashSet<Connection>();
                    if (!_activeConnections.TryAdd(accountName, userActiveConnections))
                        _activeConnections.TryGetValue(accountName, out userActiveConnections);
                }
                con = new Connection
                {
                    HadwareId = "",
                    RelatedConnection = client,
                };
                // ReSharper disable once PossibleNullReferenceException
                userActiveConnections.Add(con);

                if (userActiveConnections.Count <= user.MaxSessions)
                {
                    client.Write((uint) Opcodes.NewSessionResult, new byte[] {1});

                    // Recieve hardware ID of client
                    //var machineId = client.GetNextPacket();
                    //if (machineId.Opcode != (uint)Opcodes.HardwareId)
                    //{
                    //    userActiveConnections.Remove(con);
                    //    return;
                    //}
                    //con.HadwareId = machineId.Content.BToString();

                    //if (userActiveConnections.All(x => x.HadwareId == con.HadwareId))
                    //{
                    //    All connections have the same hwid
                    //    client.Write((uint)Opcodes.HardwareIdResult, new byte[] { 1 });
                    //}
                    //else
                    //{
                    //    // Not all active connections of the user have the same hwid
                    //    client.Write((uint)Opcodes.HardwareIdResult, new byte[] { 2 });
                    //    userActiveConnections.Remove(con);
                    //    return;
                    //}

                }
                else
                {
                    // Too many sessions
                    client.Write((uint) Opcodes.NewSessionResult, new byte[] {2});
                    userActiveConnections.Remove(con);
                    return;
                }
                var md5 = client.GetNextPacket();
                if (md5.Opcode != (uint) Opcodes.Md5String)
                {
                    // Next packet is not md5 packet
                    userActiveConnections.Remove(con);
                    return;
                }
                var md5String = md5.Content.BToString();

                if (!Manager.IsVersionAllowed(md5String))
                {
                    // Version not allowed
                    client.Write((uint) Opcodes.Md5StringResult, new byte[] {2});
                    userActiveConnections.Remove(con);
                    return;
                }
                // Version allowed
                client.Write((uint) Opcodes.Md5StringResult, new byte[] {1});


                var botVersion = client.GetNextPacket();
                if (botVersion.Opcode != (uint) Opcodes.BotVersion)
                {
                    // Next packet is not the botversion packet
                    userActiveConnections.Remove(con);
                    return;
                }

                switch (botVersion.Content[0])
                {

                    case 3:
                        // V3 is used
                        client.Write((uint) Opcodes.BotVersionReuslt, new byte[] {1});
                        ProcessClientV3(client);
                        break;

                    case 1:
                        // V1 is used
                        if (user.UserGroup == 3) return;
                        client.Write((uint) Opcodes.BotVersionReuslt, new byte[] {1});
                        ProcessClientV1(client);
                        break;

                    default:
                        // Not v1 nor v3? Something wrong here
                        client.Write((uint) Opcodes.BotVersionReuslt, new byte[] {2});
                        userActiveConnections.Remove(con);
                        return;
                }

                Console.WriteLine(
                    $"{user.Username} started a session from {client.Ip}. Now running {userActiveConnections.Count}/{user.MaxSessions} sessions. Handling {_activeConnectionCount - _waitingSockets} sessions right now.");
                while (true)
                {
                    var pack = client.GetNextPacket();
                    if (pack.Opcode == (uint) Opcodes.Ping)
                        client.Write((uint) Opcodes.Pong);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                if (userActiveConnections != null && con != null)
                {
                    userActiveConnections.Remove(con);
                    Console.WriteLine($"Session of {user.Username} from {client.Ip} got terminated. User has {userActiveConnections.Count} active sessions left.");
                }
            }
            try
            {
                client.CloseConnection();
            }
            catch { }
        }

        private static void ProcessClientV1(Client client)
        {
            client.WriteRandomly(10,
                new PacketModel
                {
                    Opcode = (uint) Opcodes.WardenLoadDetour,
                    Content = SendOvers.WardenLoadDetour.ToByte()
                },
                new PacketModel
                {
                    Opcode = (uint)Opcodes.WardenMemCpyDetour,
                    Content = SendOvers.WardenMemScan.ToByte()
                });
        }

        private static void ProcessClientV3(Client client)
        {
            client.WriteRandomly(10,
                new PacketModel
                {
                    Opcode = (uint)Opcodes.WardenLoadDetour,
                    Content = SendOvers.WardenLoadDetour.ToByte()
                },
                new PacketModel
                {
                    Opcode = (uint)Opcodes.WardenMemCpyDetour,
                    Content = SendOvers.WardenMemScan.ToByte()
                },
                new PacketModel
                {
                    Opcode = (uint)Opcodes.EventSignalDetour,
                    Content = SendOvers.EventSignal.ToByte()
                },
                new PacketModel
                {
                    Opcode = (uint)Opcodes.EventSignal_0Detour,
                    Content = SendOvers.EventSignal0.ToByte()
                },
                new PacketModel
                {
                    Opcode = (uint)Opcodes.WardenPageScanDetour,
                    Content = SendOvers.WardenPageScan.ToByte()
                });
        }
    }
}