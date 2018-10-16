using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DevOne.Security.Cryptography.BCrypt;

namespace ZzukBotAuthenticationServer.AuthServer.Users
{
    internal static class Manager
    {
        private static Dictionary<string, UserInfo> _userInfoByName = new Dictionary<string, UserInfo>();
        private static Dictionary<string, UserInfo> _userInfoByEmail = new Dictionary<string, UserInfo>();
        private static HashSet<string> _allowedVersions = new HashSet<string>();
        private static int Interval { get; } = 180000;

        internal static bool IsVersionAllowed(string md5)
        {
            return _allowedVersions.Contains(md5);
        }

        internal static UserInfo GetUserDetails(string nameOrEmail, string password)
        {
            nameOrEmail = nameOrEmail.ToLower();
            UserInfo ret;
            if (!_userInfoByEmail.TryGetValue(nameOrEmail, out ret))
            {
                _userInfoByName.TryGetValue(nameOrEmail, out ret);
            }
            if (ret == null) return null;
            var pwHashed = BCryptHelper.HashPassword(password, "$2a$13$" + ret.PasswordSalt);
            return pwHashed != ret.HashedPassword ? null : ret;
        }

        internal static async void StartUpdater()
        {
            while (true)
            {
                //try
                {
                    using (var context = new Entities.zzuk_ipbEntities())
                    {
                        var allMembers = context.core_members
                            .Where(x => x.member_group_id == 7 || x.member_group_id == 4 || x.member_group_id == 6
                            || x.member_group_id == 8 || x.member_group_id == 3)
                            .Select(x => new UserInfo
                            {
                                HashedPassword = x.members_pass_hash,
                                UserId = (int)x.member_id,
                                UserGroup = x.member_group_id,
                                PasswordSalt = x.members_pass_salt,
                                Username = x.members_seo_name,
                                Email = x.email.ToLower(),
                            })
                            .ToList();

                        var offset = (int)((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds();

                        var purchases = context.nexus_purchases
                            .Where(
                                x =>
                                    x.ps_active && !x.ps_cancelled && offset < x.ps_expire &&
                                    (x.ps_item_id == 1 || x.ps_item_id == 4 || x.ps_item_id == 5))
                            .GroupBy(x => x.ps_member)
                            .Select(x => x.AsQueryable().OrderByDescending(y => y.ps_expire).FirstOrDefault())
                            .ToDictionary(x => (int) x.ps_member,
                                x => 10);

                        foreach (var item in allMembers)
                        {
                            int sessions;
                            if (!purchases.TryGetValue(item.UserId, out sessions))
                                sessions = 10;
                            item.MaxSessions = sessions;
                        }

                        var hashSet = new HashSet<string>();
                        foreach (var item in context.zzukbot_versions)
                            hashSet.Add(item.Md5);
                        _allowedVersions = hashSet;
                        _userInfoByName = allMembers.ToDictionary(x => x.Username.ToLower(), x => x);
                        _userInfoByEmail = allMembers.ToDictionary(x => x.Email.ToLower(), x => x);

                        Console.WriteLine($"Retrieved {_userInfoByEmail.Count} active users");

                        Console.WriteLine(_allowedVersions.Aggregate($"Following md5s are allowed to run:", (s, s1) => s + " " + s1));
                    }
                }
                //catch (Exception e)
                //{
                //    Console.WriteLine("Got an exception: " + e);
                //}
                await Task.Delay(Interval);
            }
        }
    }
}