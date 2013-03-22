namespace OAuth2Server.Controllers
{
    using System;
    using System.Net;
    using System.Web.Mvc;

    using DotNetOpenAuth.OAuth2;

    using OAuth2Server.ViewModels.Home;

    /// <summary>
    /// This controller will server as a test client, allowing the user
    /// </summary>
    [RequireHttps]
    public class HomeController : Controller
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HomeController"/> class.
        /// </summary>
        public HomeController()
        {
            // DotNetOpenAuth only issues access tokens when the client uses an HTTPS connection. As we will most
            // likely run the server on our local development machine with only a self-signed SSL certificate, setting up 
            // connection to the server will fail as the SSL certificate is considered invalid by the .NET framework. 
            // To circumvent this, we add the line below that will consider all SSL certificates as valid, including
            // self-signed certificaties. Note: this should only be used for testing purposes.
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true;
        }

        /// <summary>
        /// Gets the description of the authorization server to which we will be connecting. The most important component
        /// is the token endpoint, which is the URL at which the server listens for token requests.
        /// </summary>
        /// <value>
        /// The authorization server description.
        /// </value>
        private AuthorizationServerDescription AuthorizationServerDescription
        {
            get
            {
                return new AuthorizationServerDescription
                           {
                               TokenEndpoint = new Uri(this.Url.Action("Index", "Tokens", routeValues: null, protocol: this.Request.Url.Scheme)),
                               ProtocolVersion = ProtocolVersion.V20
                           };
            }
        }

        /// <summary>
        /// This action will show a short introduction on what can be done with this website.
        /// </summary>
        /// <returns>The view result.</returns>
        [HttpGet]
        public ViewResult Index()
        {
            return this.View();
        }

        /// <summary>
        /// This action will allow the user to expirement with the OAuth 2 client credentials grant workflow. 
        /// </summary>
        /// <remarks>See: http://tools.ietf.org/html/rfc6749#section-4.4 </remarks>
        /// <returns>The view result.</returns>
        [HttpGet]
        public ViewResult ClientCredentialsGrant()
        {
            // We will set-up correct default values to make it easier for the user to start testing
            var model = new ClientCredentialsGrantViewModel { ClientId = "demo-identifier", ClientSecret = "demo-secret", Scope = "demo-scope-client" };

            return this.View(model);
        }

        /// <summary>
        /// This action will show the user the result of his OAuth 2 client credentials grant workflow request. 
        /// </summary>
        /// <remarks>See: http://tools.ietf.org/html/rfc6749#section-4.4 </remarks>
        /// <returns>The view result.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ViewResult ClientCredentialsGrant(ClientCredentialsGrantViewModel model)
        {
            if (this.ModelState.IsValid)
            {
                try
                {
                    // Create the client with which we will be connecting to the server.
                    var webServerClient = new WebServerClient(this.AuthorizationServerDescription, clientIdentifier: model.ClientId, clientSecret: model.ClientSecret);

                    // The scope that we request for the client. Note: this can also be null if we don't want to request any specific 
                    // scope or more than one scope if we want to request an access token that is valid for several scopes
                    var clientScopes = OAuthUtilities.SplitScopes(model.Scope ?? string.Empty);

                    // Request a new client access token for the specified scopes (http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.4)
                    // This method will use the client identifier and client secret used when constructing the WebServerAgentClient instance
                    this.ViewBag.AccessToken = webServerClient.GetClientAccessToken(clientScopes);
                }
                catch (Exception ex)
                {
                    this.ViewBag.Exception = ex;
                }
            }

            return this.View(model);
        }

        /// <summary>
        /// This action will allow the user to expirement with the OAuth 2 resource owner credentials grant workflow.
        /// </summary>
        /// <remarks>See: http://tools.ietf.org/html/rfc6749#section-4.3 </remarks>
        /// <returns>The view result.</returns>
        [HttpGet]
        public ViewResult ResourceOwnerCredentialsGrant()
        {
            // We will set-up correct default values to make it easier for the user to start testing
            var model = new ResourceOwnerCredentialsGrantViewModel
                            {
                                Username = "demo-username", Password = "demo-password", ClientId = "demo-identifier", Scope = "demo-scope-user"
                            };

            return this.View(model);
        }

        /// <summary>
        /// This action will show the user the result of his OAuth 2 resource owner credentials grant workflow request. 
        /// </summary>
        /// <remarks>See: http://tools.ietf.org/html/rfc6749#section-4.3 </remarks>
        /// <returns>The view result.</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ViewResult ResourceOwnerCredentialsGrant(ResourceOwnerCredentialsGrantViewModel model)
        {
            if (this.ModelState.IsValid)
            {
                try
                {
                    // Create the client with which we will be connecting to the server.
                    var webServerClient = new WebServerClient(this.AuthorizationServerDescription, clientIdentifier: model.ClientId);

                    // The scope that we request for the user. Note: this can also be null if we don't want to request any specific 
                    // scope or more than one scope if we want to request an access token that is valid for several scopes
                    var userScopes = OAuthUtilities.SplitScopes(model.Scope ?? string.Empty);

                    // Request a new user access token for the specified user and the specified scopes (http://tools.ietf.org/html/draft-ietf-oauth-v2-31#page-35)
                    this.ViewBag.AccessToken = webServerClient.ExchangeUserCredentialForToken("demo-username", "demo-password", userScopes);
                }
                catch (Exception ex)
                {
                    this.ViewBag.Exception = ex;
                }
            }

            return this.View(model);
        }
    }
}