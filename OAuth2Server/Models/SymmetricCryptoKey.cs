namespace OAuth2Server.Models
{
    using System;

    public class SymmetricCryptoKey
    {
        public virtual string Bucket { get; set; }
        public virtual string Handle { get; set; }
        public virtual DateTime ExpiresUtc { get; set; }
        public virtual byte[] Secret { get; set; }
    }
}