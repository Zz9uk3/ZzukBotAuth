//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace ZzukBotAuthenticationServer.Entities
{
    using System;
    using System.Collections.Generic;
    
    public partial class zzukbot_migrated_users
    {
        public long id { get; set; }
        public decimal user_id { get; set; }
        public System.DateTime til { get; set; }
    
        public virtual core_members core_members { get; set; }
    }
}