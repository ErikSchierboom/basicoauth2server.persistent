namespace OAuth2Server.Models
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Web;

    using DotNetOpenAuth.Messaging.Bindings;
    using DotNetOpenAuth.OAuth2;
    using DotNetOpenAuth.OAuth2.ChannelElements;
    using DotNetOpenAuth.OAuth2.Messages;
    using DotNetOpenAuth.OpenId.Provider;

    /// <summary>
    /// Our implementation of the <see cref="IAuthorizationServerHost"/> interface. This class will be the heart of the
    /// OAuth 2.0 server, as it will handle all token requests.
    /// </summary>
    internal class AuthorizationServerHost : IAuthorizationServerHost
    {
        /// <summary>
        /// The default resource server public key used for encrypting access tokens. In a real-life situation, you would
        /// get this from a certificate file.
        /// </summary>
        private static readonly RSAParameters ResourceServerEncryptionPublicKey = new RSAParameters
                                                                                      {
                                                                                          Exponent = new byte[] { 1, 0, 1 },
                                                                                          Modulus = new byte[] { 166, 175, 117, 169, 211, 251, 45, 215, 55, 53, 202, 65, 153, 155, 92, 219, 235, 243, 61, 170, 101, 250, 221, 214, 239, 175, 238, 175, 239, 20, 144, 72, 227, 221, 4, 219, 32, 225, 101, 96, 18, 33, 117, 176, 110, 123, 109, 23, 29, 85, 93, 50, 129, 163, 113, 57, 122, 212, 141, 145, 17, 31, 67, 165, 181, 91, 117, 23, 138, 251, 198, 132, 188, 213, 10, 157, 116, 229, 48, 168, 8, 127, 28, 156, 239, 124, 117, 36, 232, 100, 222, 23, 52, 186, 239, 5, 63, 207, 185, 16, 137, 73, 137, 147, 252, 71, 9, 239, 113, 27, 88, 255, 91, 56, 192, 142, 210, 21, 34, 81, 204, 239, 57, 60, 140, 249, 15, 101 },
                                                                                      };

        /// <summary>
        /// The authorization server signing key, which is used for private signing operations. In a real-life situation, you would
        /// get this from a certificate file.
        /// </summary>
        private static readonly RSAParameters AuthorizationServerSigningKey = new RSAParameters
                                                                                  {
                                                                                      Exponent = new byte[] { 1, 0, 1 },
                                                                                      Modulus = new byte[] { 210, 95, 53, 12, 203, 114, 150, 23, 23, 88, 4, 200, 47, 219, 73, 54, 146, 253, 126, 121, 105, 91, 118, 217, 182, 167, 140, 6, 67, 112, 97, 183, 66, 112, 245, 103, 136, 222, 205, 28, 196, 45, 6, 223, 192, 76, 56, 180, 90, 120, 144, 19, 31, 193, 37, 129, 186, 214, 36, 53, 204, 53, 108, 133, 112, 17, 133, 244, 3, 12, 230, 29, 243, 51, 79, 253, 10, 111, 185, 23, 74, 230, 99, 94, 78, 49, 209, 39, 95, 213, 248, 212, 22, 4, 222, 145, 77, 190, 136, 230, 134, 70, 228, 241, 194, 216, 163, 234, 52, 1, 64, 181, 139, 128, 90, 255, 214, 60, 168, 233, 254, 110, 31, 102, 58, 67, 201, 33 },
                                                                                      P = new byte[] { 237, 238, 79, 75, 29, 57, 145, 201, 57, 177, 215, 108, 40, 77, 232, 237, 113, 38, 157, 195, 174, 134, 188, 175, 121, 28, 11, 236, 80, 146, 12, 38, 8, 12, 104, 46, 6, 247, 14, 149, 196, 23, 130, 116, 141, 137, 225, 74, 84, 111, 44, 163, 55, 10, 246, 154, 195, 158, 186, 241, 162, 11, 217, 77 },
                                                                                      Q = new byte[] { 226, 89, 29, 67, 178, 205, 30, 152, 184, 165, 15, 152, 131, 245, 141, 80, 150, 3, 224, 136, 188, 248, 149, 36, 200, 250, 207, 156, 224, 79, 150, 191, 84, 214, 233, 173, 95, 192, 55, 123, 124, 255, 53, 85, 11, 233, 156, 66, 14, 27, 27, 163, 108, 199, 90, 37, 118, 38, 78, 171, 80, 26, 101, 37 },
                                                                                      DP = new byte[] { 108, 176, 122, 132, 131, 187, 50, 191, 203, 157, 84, 29, 82, 100, 20, 205, 178, 236, 195, 17, 10, 254, 253, 222, 226, 226, 79, 8, 10, 222, 76, 178, 106, 230, 208, 8, 134, 162, 1, 133, 164, 232, 96, 109, 193, 226, 132, 138, 33, 252, 15, 86, 23, 228, 232, 54, 86, 186, 130, 7, 179, 208, 217, 217 },
                                                                                      DQ = new byte[] { 175, 63, 252, 46, 140, 99, 208, 138, 194, 123, 218, 101, 101, 214, 91, 65, 199, 196, 220, 182, 66, 73, 221, 128, 11, 180, 85, 198, 202, 206, 20, 147, 179, 102, 106, 170, 247, 245, 229, 127, 81, 58, 111, 218, 151, 76, 154, 213, 114, 2, 127, 21, 187, 133, 102, 64, 151, 7, 245, 229, 34, 50, 45, 153 },
                                                                                      InverseQ = new byte[] { 137, 156, 11, 248, 118, 201, 135, 145, 134, 121, 14, 162, 149, 14, 98, 84, 108, 160, 27, 91, 230, 116, 216, 181, 200, 49, 34, 254, 119, 153, 179, 52, 231, 234, 36, 148, 71, 161, 182, 171, 35, 182, 46, 164, 179, 100, 226, 71, 119, 23, 0, 16, 240, 4, 30, 57, 76, 109, 89, 131, 56, 219, 71, 206 },
                                                                                      D = new byte[] { 108, 15, 123, 176, 150, 208, 197, 72, 23, 53, 159, 63, 53, 85, 238, 197, 153, 187, 156, 187, 192, 226, 186, 170, 26, 168, 245, 196, 65, 223, 248, 81, 170, 79, 91, 191, 83, 15, 31, 77, 39, 119, 249, 143, 245, 183, 49, 105, 115, 15, 122, 242, 87, 221, 94, 230, 196, 146, 59, 7, 103, 94, 9, 223, 146, 180, 189, 86, 190, 94, 242, 59, 32, 54, 23, 181, 124, 170, 63, 172, 90, 158, 169, 140, 6, 102, 170, 0, 135, 199, 35, 196, 212, 238, 196, 56, 14, 0, 140, 197, 169, 240, 156, 43, 182, 123, 102, 79, 89, 20, 120, 171, 43, 223, 58, 190, 230, 166, 185, 162, 186, 226, 31, 206, 196, 188, 104, 1 },
                                                                                  };

        /// <summary>
        /// Standard, in-memory provider application store that is used a crypto key- and nonce store.
        /// </summary>
        private readonly StandardProviderApplicationStore standardProviderApplicationStore;

        public AuthorizationServerHost()
        {
            // Use a default in-memory provider application store. This is a class that is ideal for use in test
            // applications as it requires no further setup and can be used as both the crypto key- and nonce store.
            // In real-life situations you would of course implement your own crypto key- and nonce store, which will
            // most likely use some kind of persistent storage to store keys and nonces. As the nonces are kept in memory
            // only, it is not possible to refresh tokens as the issued tokens will have been removed from memory the moment
            // the refresh token request is being processed
            this.standardProviderApplicationStore = new StandardProviderApplicationStore();
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
                return this.standardProviderApplicationStore;
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
                return this.standardProviderApplicationStore;
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
            accessToken.ResourceServerEncryptionKey = CreateRsaCryptoServiceProvider(ResourceServerEncryptionPublicKey);
            accessToken.AccessTokenSigningKey = CreateRsaCryptoServiceProvider(AuthorizationServerSigningKey);

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
            // We use a hard-code client identifier and secret. In real-life situations it is quite likely that you
            // will store your clients in a persistent store. Retrieving the client would then mean retrieving it 
            // from the store
            if (clientIdentifier == "demo-identifier")
            {
                return new ClientDescription("demo-secret", null, ClientType.Public);    
            }

            // If there is no client with the specified identifier, throw an ArgumentException. Note: you should
            // not return null
            throw new ArgumentException("No client could be found with the specified client identifier.", "clientIdentifier");
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
            // We check once again if the user is authorized for the specified scopes
            return UserIsAuthorizedForRequestedScopes(authorization.User, authorization.Scope);
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
            // We use a fixed username and password to determine if the username/password combination is correct. Of course, a real-life application
            // would probably use a persistent store and check if the username and password combination matches on of the stored users
            var userCredentialsAreCorrect = userName == "demo-username" && password == "demo-password";

            // The token request is approved when the user credentials are correct and the user is authorized for the requested scopes
            var isApproved = userCredentialsAreCorrect && UserIsAuthorizedForRequestedScopes(userName, accessRequest.Scope);

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
            // We define the scopes the client is authorized for. Once again, you would expect these scopes to be retrieved from
            // a persistent store. Note: the scopes a client is authorized for can very well differ between clients
            var scopesClientIsAuthorizedFor = new HashSet<string>(OAuthUtilities.ScopeStringComparer);
            scopesClientIsAuthorizedFor.Add("demo-scope-client");

            // Check if the scopes that are being requested are a subset of the scopes the user is authorized for.
            // If not, that means that the user has requested at least one scope it is not authorized for
            var clientIsAuthorizedForRequestedScopes = accessRequest.Scope.IsSubsetOf(scopesClientIsAuthorizedFor);

            // The token request is approved when the client is authorized for the requested scopes
            var isApproved = clientIsAuthorizedForRequestedScopes;

            return new AutomatedAuthorizationCheckResponse(accessRequest, isApproved);
        }

        /// <summary>
        /// Check if the user is authorized.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="requestedScopes">The scopes the user has requested.</param>
        /// <returns><c>true</c>, if the user is authorized for the specified scopes; otherwise, <c>false</c>.</returns>
        private static bool UserIsAuthorizedForRequestedScopes(string userName, HashSet<string> requestedScopes)
        {
            // We define the scopes the user is authorized for. Once again, you would expect these scopes to be retrieved from
            // a persistent store. Note: the scopes a user is authorized for can very well differ between users. Think of an
            // admin user being authorized for more scopes than a regular user
            var scopesUserIsAuthorizedFor = new HashSet<string>(OAuthUtilities.ScopeStringComparer);
            scopesUserIsAuthorizedFor.Add("demo-scope-user");

            // Check if the scopes that are being requested are a subset of the scopes the user is authorized for.
            // If not, that means that the user has requested at least one scope it is not authorized for
            var userIsAuthorizedForRequestedScopes = requestedScopes.IsSubsetOf(scopesUserIsAuthorizedFor);
            
            return userIsAuthorizedForRequestedScopes;
        }

        /// <summary>
        /// Creates the RSA crypto service provider.
        /// </summary>
        /// <param name="parameters">The RSA parameters</param>
        /// <returns>The RSA crypto service provider.</returns>
        private static RSACryptoServiceProvider CreateRsaCryptoServiceProvider(RSAParameters parameters)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameters);
            return rsa;
        }
    }
}