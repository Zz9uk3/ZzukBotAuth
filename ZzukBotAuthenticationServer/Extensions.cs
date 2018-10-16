using System;
using System.IO;
using System.Text;

namespace ZzukBotAuthenticationServer
{
    internal static class Extensions
    {
        internal static void Log(this string value, string logFile, bool showInConsole = true)
        {
            File.AppendAllText(logFile + ".txt", value + Environment.NewLine);
            if (!showInConsole) return;
            Console.WriteLine(value);
        }


        internal static string BToString(this byte[] value)
        {
            return Encoding.Unicode.GetString(value);
        }

        internal static byte[] ToByte(this string value)
        {
            return Encoding.Unicode.GetBytes(value);
        }

        internal static long ToUnixTimeSeconds(this DateTime value)
        {
            DateTimeOffset offset = DateTime.SpecifyKind(value, DateTimeKind.Utc);
            return offset.ToUnixTimeSeconds();
        }
    }
}