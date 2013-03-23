namespace OAuth2Server.Models
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Data.Linq;
    using System.Data.SqlClient;
    using System.Linq;

    using DotNetOpenAuth.Messaging.Bindings;

    using OAuth2Server.Helpers;

    /// <summary>
    /// A database-persisted nonce- and crypto key store.
    /// </summary>
    internal class DatabaseKeyNonceStore : INonceStore, ICryptoKeyStore
    {
        private readonly OAuth2ServerDbContext db = new OAuth2ServerDbContext();

        /// <summary>
        /// Stores a given nonce and timestamp.
        /// </summary>
        /// <param name="context">The context, or namespace, within which the
        /// <paramref name="nonce"/> must be unique.
        /// The context SHOULD be treated as case-sensitive.
        /// The value will never be <c>null</c> but may be the empty string.</param>
        /// <param name="nonce">A series of random characters.</param>
        /// <param name="timestampUtc">The UTC timestamp that together with the nonce string make it unique
        /// within the given <paramref name="context"/>.
        /// The timestamp may also be used by the data store to clear out old nonces.</param>
        /// <returns>
        /// True if the context+nonce+timestamp (combination) was not previously in the database.
        /// False if the nonce was stored previously with the same timestamp and context.
        /// </returns>
        /// <remarks>
        /// The nonce must be stored for no less than the maximum time window a message may
        /// be processed within before being discarded as an expired message.
        /// This maximum message age can be looked up via the
        /// <see cref="DotNetOpenAuth.Configuration.MessagingElement.MaximumMessageLifetime"/>
        /// property, accessible via the <see cref="Configuration"/>
        /// property.
        /// </remarks>
        public bool StoreNonce(string context, string nonce, DateTime timestampUtc)
        {
            this.db.Nonces.Add(new Nonce { Context = context, Code = nonce, Timestamp = timestampUtc });
            try
            {
                this.db.SaveChanges();
                return true;
            }
            catch (DuplicateKeyException)
            {
                return false;
            }
            catch (SqlException)
            {
                return false;
            }
        }

        public CryptoKey GetKey(string bucket, string handle)
        {
            // It is critical that this lookup be case-sensitive, which can only be configured at the database.
            var cryptoKey = (from key in this.db.SymmetricCryptoKeys where key.Bucket == bucket && key.Handle == handle select key).FirstOrDefault();

            if (cryptoKey == null)
            {
                return null;
            }

            return new CryptoKey(cryptoKey.Secret, cryptoKey.ExpiresUtc.AsUtc());
        }

        public IEnumerable<KeyValuePair<string, CryptoKey>> GetKeys(string bucket)
        {
            // Find all the symmetric crypto keys belonging to the specified bucket. We need to call ToEnumerable() on the
            // result to force the query to execute. If we wouldn't do this, the statement below where the result is
            // transformed to KeyValuePair's would fail (as the KeyValuePair class does not have a parameterless constructor)
            var symmetricCryptoKeys = (from key in this.db.SymmetricCryptoKeys where key.Bucket == bucket orderby key.ExpiresUtc descending select key).AsEnumerable();
            
            return symmetricCryptoKeys.Select(k => new KeyValuePair<string, CryptoKey>(k.Handle, new CryptoKey(k.Secret, k.ExpiresUtc.AsUtc())));
        }

        public void StoreKey(string bucket, string handle, CryptoKey key)
        {
            var keyRow = new SymmetricCryptoKey { Bucket = bucket, Handle = handle, Secret = key.Key, ExpiresUtc = key.ExpiresUtc, };

            this.db.SymmetricCryptoKeys.Add(keyRow);
            this.db.SaveChanges();
        }

        public void RemoveKey(string bucket, string handle)
        {
            var match = this.db.SymmetricCryptoKeys.FirstOrDefault(k => k.Bucket == bucket && k.Handle == handle);
            if (match != null)
            {
                this.db.SymmetricCryptoKeys.Remove(match);
            }
        }
    }
}