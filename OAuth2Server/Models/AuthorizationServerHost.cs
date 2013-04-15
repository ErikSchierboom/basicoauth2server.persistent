namespace OAuth2Server.Models
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using DotNetOpenAuth.Messaging.Bindings;
    using DotNetOpenAuth.OAuth2;
    using DotNetOpenAuth.OAuth2.ChannelElements;
    using DotNetOpenAuth.OAuth2.Messages;

    /// <summary>
    /// Our implementation of the <see cref="IAuthorizationServerHost"/> interface. This class will be the heart of the
    /// OAuth 2.0 server, as it will handle all token requests.
    /// </summary>
    internal class AuthorizationServerHost : IAuthorizationServerHost
    {   
        /// <summary>
        /// Standard, in-memory provider application store that is used a crypto key- and nonce store.
        /// </summary>
        private readonly DatabaseKeyNonceStore databaseKeyNonceStore;

        /// <summary>
        /// The database context.
        /// </summary>
        private readonly OAuth2ServerDbContext db;

        public AuthorizationServerHost()
        {
            // Use our custom nonce/symmetric key store, which will store the keys and nonces to the database
            this.databaseKeyNonceStore = new DatabaseKeyNonceStore();

            // Create the database context
            this.db = new OAuth2ServerDbContext();
        }

        /// <summary>
        /// Gets the store for storing crypto keys used to symmetrically encrypt and sign authorization codes and refresh tokens.
        /// </summary>
        /// <remarks>
        /// This store should be kept strictly confidential in the authorization server(s)
        /// and NOT shared with the resource server.  Anyone with these secrets can mint
        /// tokens to essentially grant themselves access to anything they want.
        /// </remarks>
        public ICryptoKeyStore CryptoKeyStore
        {
            get
            {
                return this.databaseKeyNonceStore;
            }
        }

        /// <summary>
        /// Gets the authorization code nonce store to use to ensure that authorization codes can only be used once.
        /// </summary>
        /// <value>
        /// The authorization code nonce store.
        /// </value>
        public INonceStore NonceStore
        {
            get
            {
                return this.databaseKeyNonceStore;
            }
        }

        /// <summary>
        /// Acquires the access token and related parameters that go into the formulation of the token endpoint's response to a client.
        /// </summary>
        /// <param name="accessTokenRequestMessage">Details regarding the resources that the access token will grant access to, and the identity of the client
        /// that will receive that access.
        /// Based on this information the receiving resource server can be determined and the lifetime of the access
        /// token can be set based on the sensitivity of the resources.</param>
        /// <returns>
        /// A non-null parameters instance that DotNetOpenAuth will dispose after it has been used.
        /// </returns>
        public AccessTokenResult CreateAccessToken(IAccessTokenRequest accessTokenRequestMessage)
        {
            var accessToken = new AuthorizationServerAccessToken();
            accessToken.Lifetime = TimeSpan.FromHours(1);
            accessToken.ResourceServerEncryptionKey = EncryptionKeys.GetResourceServerEncryptionPublicKey();
            accessToken.AccessTokenSigningKey = EncryptionKeys.GetAuthorizationServerSigningPrivateKey();

            return new AccessTokenResult(accessToken);
        }

        /// <summary>
        /// Gets the client with a given identifier.
        /// </summary>
        /// <param name="clientIdentifier">The client identifier.</param>
        /// <returns>
        /// The client registration.  Never null.
        /// </returns>
        public IClientDescription GetClient(string clientIdentifier)
        {
            // Try to find the client with the specified identifier
            var client = this.db.Clients.SingleOrDefault(consumerCandidate => consumerCandidate.ClientIdentifier == clientIdentifier);

            // Throw an exception if no client with the specified identifier could be found
            if (client == null)
            {
                throw new ArgumentOutOfRangeException("clientIdentifier");
            }

            return client;
        }

        /// <summary>
        /// Determines whether a described authorization is (still) valid.
        /// </summary>
        /// <param name="authorization">The authorization.</param>
        /// <returns>
        ///   <c>true</c> if the original authorization is still valid; otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        ///   <para>When establishing that an authorization is still valid,
        /// it's very important to only match on recorded authorizations that
        /// meet these criteria:</para>
        /// 1) The client identifier matches.
        /// 2) The user account matches.
        /// 3) The scope on the recorded authorization must include all scopes in the given authorization.
        /// 4) The date the recorded authorization was issued must be <em>no later</em> that the date the given authorization was issued.
        ///   <para>One possible scenario is where the user authorized a client, later revoked authorization,
        /// and even later reinstated authorization.  This subsequent recorded authorization
        /// would not satisfy requirement #4 in the above list.  This is important because the revocation
        /// the user went through should invalidate all previously issued tokens as a matter of
        /// security in the event the user was revoking access in order to sever authorization on a stolen
        /// account or piece of hardware in which the tokens were stored. </para>
        /// </remarks>
        public bool IsAuthorizationValid(IAuthorizationDescription authorization)
        {
            // Try to find a user with the specified username and password
            var user = this.db.Users.FirstOrDefault(u => u.OpenIDClaimedIdentifier == authorization.User);

            // If no user was found with the specified username/password combination, the authorization is not valid
            if (user == null)
            {
                return false;
            }

            // Try to find the authorization the user has with the specified client 
            var userAuthorizationForClient = user.Authorizations.FirstOrDefault(a => a.Client.ClientIdentifier == authorization.ClientIdentifier);

            // If no user authorization was found, that means that the user is not authorized for the specified client. 
            // As a consequence, the authorization is not valid
            if (userAuthorizationForClient == null)
            {
                return false;
            }

            // We check once again if the user is authorized for the specified scopes
            return RequestedScopeIsValid(authorization.Scope, OAuthUtilities.SplitScopes(userAuthorizationForClient.Scope));
        }

        /// <summary>
        /// Determines whether a given set of resource owner credentials is valid based on the authorization server's user database
        /// and if so records an authorization entry such that subsequent calls to <see cref="M:DotNetOpenAuth.OAuth2.IAuthorizationServerHost.IsAuthorizationValid(DotNetOpenAuth.OAuth2.ChannelElements.IAuthorizationDescription)" /> would
        /// return <c>true</c>.
        /// </summary>
        /// <param name="userName">Username on the account.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="accessRequest">The access request the credentials came with.
        /// This may be useful if the authorization server wishes to apply some policy based on the client that is making the request.</param>
        /// <returns>
        /// A value that describes the result of the authorization check.
        /// </returns>
        public AutomatedUserAuthorizationCheckResponse CheckAuthorizeResourceOwnerCredentialGrant(string userName, string password, IAccessTokenRequest accessRequest)
        {
            // Try to find a user with the specified username and password
            var user = this.db.Users.FirstOrDefault(u => u.OpenIDClaimedIdentifier == userName && u.Password == password);

            // If no user was found with the specified username/password combination, do not authorize the request
            if (user == null)
            {
                return new AutomatedUserAuthorizationCheckResponse(accessRequest, false, userName);
            }

            // Try to find the authorization the user has with the specified client 
            var userAuthorizationForClient = user.Authorizations.FirstOrDefault(a => a.Client.ClientIdentifier == accessRequest.ClientIdentifier);

            // If no user authorization was found, that means that the user is not authorized for the specified client. 
            // As a consequence, we do not authorize the request
            if (userAuthorizationForClient == null)
            {
                return new AutomatedUserAuthorizationCheckResponse(accessRequest, false, userName);
            }

            // At this point we have verified that user credentials were valid and that the user has an authorization specified
            // for the requested client. All that remains is to check if that authorization gives the user enough rights for
            // the requested scopes.
            var isApproved = RequestedScopeIsValid(accessRequest.Scope, OAuthUtilities.SplitScopes(userAuthorizationForClient.Scope));

            return new AutomatedUserAuthorizationCheckResponse(accessRequest, isApproved, userName);
        }

        /// <summary>
        /// Determines whether an access token request given a client credential grant should be authorized
        /// and if so records an authorization entry such that subsequent calls to <see cref="M:DotNetOpenAuth.OAuth2.IAuthorizationServerHost.IsAuthorizationValid(DotNetOpenAuth.OAuth2.ChannelElements.IAuthorizationDescription)" /> would
        /// return <c>true</c>.
        /// </summary>
        /// <param name="accessRequest">The access request the credentials came with.
        /// This may be useful if the authorization server wishes to apply some policy based on the client that is making the request.</param>
        /// <returns>
        /// A value that describes the result of the authorization check.
        /// </returns>
        public AutomatedAuthorizationCheckResponse CheckAuthorizeClientCredentialsGrant(IAccessTokenRequest accessRequest)
        {
            // Find the client
            var client = this.db.Clients.Single(consumerCandidate => consumerCandidate.ClientIdentifier == accessRequest.ClientIdentifier);

            // Parse the scopes the client is authorized for
            var scopesClientIsAuthorizedFor = OAuthUtilities.SplitScopes(client.Scope);

            // Check if the scopes that are being requested are a subset of the scopes the user is authorized for.
            // If not, that means that the user has requested at least one scope it is not authorized for
            var clientIsAuthorizedForRequestedScopes = accessRequest.Scope.IsSubsetOf(scopesClientIsAuthorizedFor);

            // The token request is approved when the client is authorized for the requested scopes
            var isApproved = clientIsAuthorizedForRequestedScopes;

            return new AutomatedAuthorizationCheckResponse(accessRequest, isApproved);
        }

        /// <summary>
        /// Check if the requested scope is valid.
        /// </summary>
        /// <param name="requestedScope">The scope the user has requested.</param>
        /// <param name="authorizedScope">The scope the user is authorized for.</param>
        /// <returns><c>true</c>, if the user is authorized for the specified scope; otherwise, <c>false</c>.</returns>
        private static bool RequestedScopeIsValid(HashSet<string> requestedScope, HashSet<string> authorizedScope)
        {
            // Check if the requested scope is a subset of the authorized scope. 
            // If not, that means that the user has requested at least one scope it is not authorized for
            return requestedScope.IsSubsetOf(authorizedScope);
        }
    }
}