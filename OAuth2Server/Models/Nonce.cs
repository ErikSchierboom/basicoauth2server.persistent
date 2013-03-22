namespace OAuth2Server.Models
{
    using System;

    public class Nonce
    {
        public virtual string Context { get; set; }
        public virtual string Code { get; set; }
        public virtual DateTime Timestamp { get; set; }
    }
}