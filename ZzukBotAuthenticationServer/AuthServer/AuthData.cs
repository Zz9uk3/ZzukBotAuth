using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;

namespace ZzukBotAuthenticationServer.AuthServer
{
    internal class AuthData
    {
        internal static bool SettingsCreated => File.Exists(_settingFile);
        internal static void Create()
        {
            var settings = JsonConvert.SerializeObject(new AuthData());
            File.WriteAllText(_settingFile, settings);
        }

        private static readonly Lazy<AuthData> _instance = new Lazy<AuthData>(() => JsonConvert.DeserializeObject<AuthData>(File.ReadAllText(_settingFile)));
        private static string _settingFile
            => Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\Settings.json";
        private static readonly object _lockObj = new object();
        internal static AuthData Instance
        {
            get
            {
                lock (_lockObj)
                {
                    return _instance.Value;
                }
            }
        }
        private AuthData()
        {
            Port = 6200;
            MaxWaitingSockets = 5;
            MaxClients = 2000;
            Timeout = 60000;
        }

        /// <summary>
        /// Bind to any IP?
        /// </summary>
        internal IPAddress IpAddress => IPAddress.Any;
        /// <summary>
        /// Port the authentication server will listen on
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Max sockets waiting for a connection
        /// </summary>
        public int MaxWaitingSockets { get; set; }

        /// <summary>
        /// Max clients the authentication server will handle
        /// </summary>
        public int MaxClients { get; set; }

        public int Timeout { get; set; }


        internal readonly X509Certificate2 Certificate = new X509Certificate2("ZzukAuth.pfx", "Emune6Uren78");
    }
}