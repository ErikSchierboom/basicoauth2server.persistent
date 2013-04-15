namespace OAuth2Server.Models
{
    using System.Threading;
    using System.Web;
    using System.Web.Mvc;

    using DotNetOpenAuth.Messaging;
    using DotNetOpenAuth.OAuth2;

    /// <summary>
    /// Allows authorization to be applied to ASP.NET MVC methods where OAuth is used as the authorization mechanism.
    /// </summary>
    public class OAuthAuthorizeAttribute : AuthorizeAttribute
    {
        /// <summary>
        /// The resource server that will be used to validate and process access tokens.
        /// </summary>
        private readonly ResourceServer resourceServer;

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthAuthorizeAttribute"/> class.
        /// </summary>
        public OAuthAuthorizeAttribute()
        {
            var standardAccessTokenAnalyzer = new StandardAccessTokenAnalyzer(EncryptionKeys.GetAuthorizationServerSigningPublicKey(), EncryptionKeys.GetResourceServerEncryptionPrivateKey());
            this.resourceServer = new ResourceServer(standardAccessTokenAnalyzer);
        }

        /// <summary>
        /// Gets or sets the scopes.
        /// </summary>
        /// <value>
        /// The required scopes.
        /// </value>
        /// <remarks>
        /// Multiple scopes can be used by separating them with spaces.
        /// </remarks>
        public string Scopes { get; set; }

        /// <summary>
        /// When overridden, provides an entry point for custom authorization checks.
        /// </summary>
        /// <param name="httpContext">The HTTP context, which encapsulates all HTTP-specific information about an individual HTTP request.</param>
        /// <returns>
        /// true if the user is authorized; otherwise, false.
        /// </returns>
        /// <exception cref="System.InvalidOperationException">Thrown when the <see cref="ResourceServer"/> property is <c>null</c>.</exception>
        /// <exception cref="System.InvalidOperationException">Thrown when the <see cref="Scopes"/> property is <c>null</c>.</exception>
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            try
            {
                this.StorePrincipalFromAccessToken(httpContext);

                return this.AccessTokenIsAuthorizedForRequestedScopes();
            }
            catch (ProtocolException)
            {
                return false;
            }
        }

        /// <summary>
        /// Processes HTTP requests that fail authorization.
        /// </summary>
        /// <param name="filterContext">Encapsulates the information for using <see cref="T:System.Web.Mvc.AuthorizeAttribute" />. The <paramref name="filterContext" /> object contains the controller, HTTP context, request context, action result, and route data.</param>
        protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
        {
            filterContext.Result = new HttpUnauthorizedResult();
        }

        /// <summary>
        /// Stores the principal contained in the current access token.
        /// </summary>
        /// <param name="httpContext">The HTTP context.</param>
        protected virtual void StorePrincipalFromAccessToken(HttpContextBase httpContext)
        {
            httpContext.User = this.resourceServer.GetPrincipal();
            Thread.CurrentPrincipal = httpContext.User;
        }

        /// <summary>
        /// Check if the access token provided is authorized for the requested scopes.
        /// </summary>
        /// <returns><c>true</c>, if the access token provided is authorized for the requested scopes; otherwise, <c>false</c>.</returns>
        protected virtual bool AccessTokenIsAuthorizedForRequestedScopes()
        {
            return OAuthUtilities.SplitScopes(this.Scopes ?? string.Empty).IsSubsetOf(this.resourceServer.GetAccessToken().Scope);
        }
    }
}