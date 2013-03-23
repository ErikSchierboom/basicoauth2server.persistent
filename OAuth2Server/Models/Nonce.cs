namespace OAuth2Server.Models
{
    using System;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    /// <summary>
    /// A nonce.
    /// </summary>
    public class Nonce
    {
        /// <summary>
        /// Gets or sets the context of the nonce.
        /// </summary>
        [Key, Column(Order = 0)]
        public virtual string Context { get; set; }

        /// <summary>
        /// Gets or sets the code of the nonce.
        /// </summary>
        [Key, Column(Order = 1)]
        public virtual string Code { get; set; }

        /// <summary>
        /// Gets or sets the timestamp of the nonce.
        /// </summary>
        [Key, Column(Order = 2)]
        public virtual DateTime Timestamp { get; set; }
    }
}