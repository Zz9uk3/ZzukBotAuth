using System;

namespace ZzukBotAuthenticationServer.Models
{
    internal class PacketModel : EventArgs
    {
        internal uint Opcode { get; set; }
        internal byte[] Content { get; set; }
    }
}