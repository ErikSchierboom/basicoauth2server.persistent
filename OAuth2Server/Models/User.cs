namespace OAuth2Server.Models
{
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;

    public class User
    {
        public User()
        {
            this.Authorizations = new HashSet<Authorization>();
        }

        /// <summary>
        /// Gets or sets the id.
        /// </summary>
        [Key]
        public virtual int Id { get; set; }

        [Required]
        public virtual string OpenIDClaimedIdentifier { get; set; }

        [Required]
        public virtual string OpenIDFriendlyIdentifier { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <remarks>
        /// Of course, in real-life examples you would not store the password in plaintext.
        /// However, for our example this makes sense.
        /// </remarks>
        [Required]
        public virtual string Password { get; set; }

        /// <summary>
        /// Gets or sets the user's authorizations.
        /// </summary>
        public virtual ISet<Authorization> Authorizations { get; set; }
    }
}