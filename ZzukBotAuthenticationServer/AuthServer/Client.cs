using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZzukBotAuthenticationServer.Models;

namespace ZzukBotAuthenticationServer.AuthServer
{
    public class Client
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _netStream;  // Raw-data stream of connection.
        private readonly BinaryReader _reader;
        private readonly BinaryWriter _writer;
        private readonly SslStream _ssl;
        private volatile bool _connected;
        private readonly object _lock = new object();
        private readonly Action<Client> _onDc;

        internal string Ip { get; private set; }

        internal Client(TcpClient client, Action<Client> onDcCallback)
        {
            _client = client;
            _onDc = onDcCallback;

            //Set our inital timeouts
            _client.ReceiveTimeout = AuthData.Instance.Timeout;
            _client.SendTimeout = AuthData.Instance.Timeout;
            //Get the raw data stream
            _netStream = _client.GetStream();
            //Replace with an SSL stream
            _ssl = new SslStream(_netStream, false);
            _ssl.AuthenticateAsServer(AuthData.Instance.Certificate, false, SslProtocols.Tls, true);
            _reader = new BinaryReader(_ssl, Encoding.UTF8);
            _writer = new BinaryWriter(_ssl, Encoding.UTF8);
            _connected = true;
            Ip = _client.Client.RemoteEndPoint.ToString().Split(':').First();
        }

        internal void Write(uint opcode, byte[] content = null)
        {
            if (!_connected) return;
            try
            {
                if (content == null)
                    content = new byte[] { 0 };
                try
                {
                    _writer.Write(opcode);
                    _writer.Write(content.Length);
                    _writer.Write(content);
                    _writer.Flush();
                }
                catch
                {
                    CloseConnection();
                }
            }
            catch (Exception e)
            {
            }
        }

        private uint GetUnusedOpcode()
        {
            return (uint)_random.Next(18, int.MaxValue);
        }

        private readonly Random _random = new Random();

        internal void WriteRandomly(int packetCount, params PacketModel[] packets)
        {
            if (packets.Length > packetCount) throw new Exception();
            var sendOn = new List<int>();
            while (sendOn.Count < packets.Length)
            {
                var nextRan = _random.Next(0, packetCount);
                if (!sendOn.Contains(nextRan))
                    sendOn.Add(nextRan);
            }
            for (var i = 0; i < packetCount; i++)
            {
                var index = sendOn.IndexOf(i);
                if (index == -1)
                {
                    Write(GetUnusedOpcode());
                    continue;
                }
                Write(packets[index].Opcode, packets[index].Content);
            }
        }

        internal PacketModel[] GetRandomly(int packetCount, params uint[] opcodes)
        {
            var opcodeList = opcodes.ToList();
            var ret = new PacketModel[opcodeList.Count];
            for (var i = 0; i < packetCount; i++)
            {
                var pack = GetNextPacket();
                var index = opcodeList.IndexOf(pack.Opcode);
                if (index != -1)
                {
                    ret[index] = pack;
                }
            }
            return ret;
        }


        internal PacketModel GetNextPacket()
        {
            try
            {
                var opcode = _reader.ReadUInt32();
                var length = _reader.ReadInt32();
                var content = _reader.ReadBytes(length);
                return new PacketModel
                {
                    Opcode = opcode,
                    Content = content
                };
            }
            catch
            {
                CloseConnection();
                return null;
            }
        }

        internal void CloseConnection()
        {
            lock (_lock)
            {
                if (!_connected) return;
                _connected = false;
                _reader.Close();
                _writer.Close();
                _ssl.Close();
                _netStream.Close();
                _client.Close();
                _onDc.Invoke(this);
            }
        }

    }
}