namespace OAuth2Server.Models
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    using DotNetOpenAuth.OAuth2;

    using OAuth2Server.Helpers;

    /// <summary>
    /// A client. The <see cref="IClientDescription"/> interface is defined in DotNetOpenAuth. To have the client
    /// implement this interface makes it easier to user clients stored in our database on DotNetOpenAuth.
    /// </summary>
    public class Client : IClientDescription
    {
        public Client()
        {
            this.Authorizations = new HashSet<Authorization>();
        }

        [Key]
        public virtual int Id { get; set; }

        [Required]
        public virtual string ClientIdentifier { get; set; }

        [Required]
        public virtual string ClientSecret { get; set; }

        public virtual string Callback { get; set; }

        [Required]
        public virtual string Name { get; set; }

        [Required]
        public virtual string Scope { get; set; }

        [Required]
        public virtual ClientType ClientType { get; set; }

        public virtual ISet<Authorization> Authorizations { get; set; }

        /// <summary>
        /// Gets the callback to use when an individual authorization request
        /// does not include an explicit callback URI.
        /// </summary>
        /// <value>
        /// An absolute URL; or <c>null</c> if none is registered.
        /// </value>
        [NotMapped]
        Uri IClientDescription.DefaultCallback
        {
            get
            {
                return string.IsNullOrEmpty(this.Callback) ? null : new Uri(this.Callback);
            }
        }

        /// <summary>
        /// Gets a value indicating whether a non-empty secret is registered for this client.
        /// </summary>
        [NotMapped]
        bool IClientDescription.HasNonEmptySecret
        {
            get
            {
                return !string.IsNullOrEmpty(this.ClientSecret);
            }
        }

        /// <summary>
        /// Determines whether a callback URI included in a client's authorization request
        /// is among those allowed callbacks for the registered client.
        /// </summary>
        /// <param name="callback">The absolute URI the client has requested the authorization result be received at.</param>
        /// <returns>
        ///   <c>true</c> if the callback URL is allowable for this client; otherwise, <c>false</c>.
        /// </returns>
        public bool IsCallbackAllowed(Uri callback)
        {
            if (string.IsNullOrEmpty(this.Callback))
            {
                // No callback rules have been set up for this client.
                return true;
            }

            // In this sample, it's enough of a callback URL match if the scheme and host match.
            // In a production app, it is advisable to require a match on the path as well.
            var acceptableCallbackPattern = new Uri(this.Callback);
            return string.Equals(acceptableCallbackPattern.GetLeftPart(UriPartial.Authority), callback.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks whether the specified client secret is correct.
        /// </summary>
        /// <param name="secret">The secret obtained from the client.</param>
        /// <returns><c>true</c> if the secret matches the one in the authorization server's record for the client; <c>false</c> otherwise.</returns>
        /// <remarks>
        /// All string equality checks, whether checking secrets or their hashes,
        /// should be done using <see cref="DateTimeUtilities.EqualsConstantTime"/> to mitigate timing attacks.
        /// </remarks>
        bool IClientDescription.IsValidClientSecret(string secret)
        {
            return DateTimeUtilities.EqualsConstantTime(secret, this.ClientSecret);
        }
    }
}