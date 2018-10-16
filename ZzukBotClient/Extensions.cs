using System.Text;

namespace ZzukBotClient
{
    internal static class Extensions
    {
        internal static string BToString(this byte[] value)
        {
            return Encoding.Unicode.GetString(value);
        }
        internal static byte[] ToByte(this string value)
        {
            return Encoding.Unicode.GetBytes(value);
        }
    }
}