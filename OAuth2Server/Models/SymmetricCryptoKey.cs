namespace OAuth2Server.Models
{
    using System;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    /// <summary>
    /// A symmetric crypto key.
    /// </summary>
    public class SymmetricCryptoKey
    {
        /// <summary>
        /// Gets or sets the bucket.
        /// </summary>
        [Key, Column(Order = 0)]
        public virtual string Bucket { get; set; }

        /// <summary>
        /// Gets or sets the handle.
        /// </summary>
        [Key, Column(Order = 1)]
        public virtual string Handle { get; set; }

        /// <summary>
        /// Gets or sets the time at which the key expires.
        /// </summary>
        public virtual DateTime ExpiresUtc { get; set; }

        /// <summary>
        /// Gets or sets the secret specific to this key.
        /// </summary>
        public virtual byte[] Secret { get; set; }
    }
}