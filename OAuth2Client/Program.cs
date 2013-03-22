namespace OAuth2Client
{
    using System;
    using System.Net;

    using DotNetOpenAuth.OAuth2;

    /// <summary>
    /// This console application shows how to connect to the OAuth 2 demo server.
    /// </summary>
    internal class Program
    {
        private static void Main()
        {
            // DotNetOpenAuth only issues access tokens when the client uses an HTTPS connection. As we will most
            // likely run the server on our local development machine with only a self-signed SSL certificate, setting up 
            // connection to the server will fail as the SSL certificate is considered invalid by the .NET framework. 
            // To circumvent this, we add the line below that will consider all SSL certificates as valid, including
            // self-signed certificaties. Note: this should only be used for testing purposes.
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true;

            // The description of the authorization server to which we will be connecting. The most important component
            // is the token endpoint, which is the URL at which the server listens for token requests
            var authorizationServerDescription = new AuthorizationServerDescription
                                                     {
                                                         TokenEndpoint = new Uri("https://localhost:44303/tokens"),
                                                         ProtocolVersion = ProtocolVersion.V20
                                                     };

            // Create the client with which we will be connecting to the server.
            var userAgentClient = new UserAgentClient(authorizationServerDescription, clientIdentifier: "demo-identifier", clientSecret: "demo-secret");

            // The scope that we request for the client. Note: this can also be null if we don't want to request any specific 
            // scope or more than one scope if we want to request an access token that is valid for several scopes
            var clientScopes = new[] { "demo-scope-client" };

            // Request a new client access token for the specified scopes (http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.4)
            // This method will use the client identifier and client secret used when constructing the UserAgentClient instance
            var clientAccessToken = userAgentClient.GetClientAccessToken(clientScopes);

            // Output some information about the retrieved client access token
            Console.WriteLine("[RETRIEVED CLIENT ACCESS TOKEN]");
            Console.WriteLine("Access token: {0}", clientAccessToken.AccessToken);
            Console.WriteLine("Expiration time: {0}", clientAccessToken.AccessTokenExpirationUtc);
            Console.WriteLine("Scope: {0}",  OAuthUtilities.JoinScopes(clientAccessToken.Scope));

            // The scope that we request for the user. Note: this can also be null if we don't want to request any specific 
            // scope or more than one scope if we want to request an access token that is valid for several scopes
            var userScopes = new[] { "demo-scope-user" };

            // Request a new user access token for the specified user and the specified scopes (http://tools.ietf.org/html/draft-ietf-oauth-v2-31#page-35)
            var userAccessToken = userAgentClient.ExchangeUserCredentialForToken("demo-username", "demo-password", userScopes);

            // Output some information about the retrieved user access token
            Console.WriteLine("\n[RETRIEVED USER ACCESS TOKEN]");
            Console.WriteLine("Access token: {0}", userAccessToken.AccessToken);
            Console.WriteLine("Refresh token: {0}", userAccessToken.RefreshToken);
            Console.WriteLine("Expiration time: {0}", userAccessToken.AccessTokenExpirationUtc);
            Console.WriteLine("Scope: {0}", OAuthUtilities.JoinScopes(userAccessToken.Scope));
            
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}