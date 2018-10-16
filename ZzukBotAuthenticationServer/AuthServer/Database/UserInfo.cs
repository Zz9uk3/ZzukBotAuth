using System;

namespace ZzukBotAuthenticationServer.AuthServer.Users
{
    internal class UserInfo
    {
        internal int UserId { get; set; }
        internal string HashedPassword { get; set; }
        internal string PasswordSalt { get; set; }
        internal int MaxSessions { get; set; }
        internal int UserGroup { get; set; }
        internal string Email { get; set; }
        internal string Username { get; set; }
    }
}