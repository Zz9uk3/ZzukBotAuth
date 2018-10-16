namespace ZzukBotAuthenticationServer.AuthServer
{
    public enum Opcodes : uint
    {
        AccountName = 0,
        AccountPassword = 1,
        Md5String = 2,
        HardwareId = 3,
        LoginResult = 4,

        EventSignal_0Detour = 5,
        EventSignalDetour = 6,
        WardenLoadDetour = 7,
        WardenPageScanDetour = 8,
        WardenMemCpyDetour = 9,

        Heartbeat = 10,

        Ping = 11,
        Pong = 12,

        BotVersion = 13,

        HardwareIdResult = 14,
        BotVersionReuslt = 15,
        Md5StringResult = 16,

        NewSessionResult = 17
    }
}