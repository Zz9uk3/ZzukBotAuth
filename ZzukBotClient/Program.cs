using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZzukBotClient.AuthClient;
using ZzukBotClient.Models;

namespace ZzukBotClient
{
    class Program
    {
        static void Main(string[] args)
        {
            Thread.Sleep(5000);
            string reason;
            if (AuthProcessor.Instance.Auth("zzuk", "123Lol123!", out reason))
            {
                Console.WriteLine("Successfully authenticated");
            }
            else
            {
                Console.WriteLine($"Authentication failed: {reason}");
            }
            Console.ReadLine();
        }
    }
}
