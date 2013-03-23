namespace OAuth2Server.Models
{
    using System.Data.Entity;

    /// <summary>
    /// The database context for our OAuth 2 server.
    /// </summary>
    public class OAuth2ServerDbContext : DbContext
    {
        /// <summary>
        /// Gets or sets the users.
        /// </summary>
        /// <value>
        /// The users.
        /// </value>
        public DbSet<User> Users { get; set; }

        /// <summary>
        /// Gets or sets the clients.
        /// </summary>
        /// <value>
        /// The clients.
        /// </value>
        public DbSet<Client> Clients { get; set; }

        /// <summary>
        /// Gets or sets the authorizations, which is basically the link between clients and users.
        /// </summary>
        /// <value>
        /// The authorizations.
        /// </value>
        public DbSet<Authorization> Authorizations { get; set; }

        /// <summary>
        /// Gets or sets the nonces.
        /// </summary>
        /// <value>
        /// The nonces.
        /// </value>
        public DbSet<Nonce> Nonces { get; set; }

        /// <summary>
        /// Gets or sets the symmetric crypto keys.
        /// </summary>
        /// <value>
        /// The symmetric crypto keys.
        /// </value>
        public DbSet<SymmetricCryptoKey> SymmetricCryptoKeys { get; set; }
    }
}