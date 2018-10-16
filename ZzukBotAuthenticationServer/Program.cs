using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ZzukBotAuthenticationServer.AuthServer;
using ZzukBotAuthenticationServer.AuthServer.Users;

namespace ZzukBotAuthenticationServer
{
    class Program
    {

        static void Main(string[] args)
        {
            Console.WriteLine("ZzukBot 3.0 Authentication Manager");
            if (!AuthData.SettingsCreated)
            {
                Console.WriteLine("Created Settings.json. Please edit it to your needs and restart the application");
                AuthData.Create();
            }
            else
            {
                Manager.StartUpdater();
                AuthServerHandler.Instance.StartAuth();
            }
            Console.ReadLine();
        }
    }
}
