namespace OAuth2Server.Controllers
{
    using System.Web.Mvc;

    using DotNetOpenAuth.Messaging;
    using DotNetOpenAuth.OAuth2;

    using OAuth2Server.Models;

    /// <summary>
    /// This controller will handle token requests. The <see cref="RequireHttpsAttribute"/> is necessary as DotNetOpenAuth
    /// will only process HTTPS requests.
    /// </summary>
    [RequireHttps]
    public class TokensController : Controller
    {
        // Create our authorization server using our own, custom IAuthorizationServerHost implementation
        private readonly AuthorizationServer authorizationServer = new AuthorizationServer(new AuthorizationServerHost());
        
        /// <summary>
        /// This action will handle all token requests. 
        /// </summary>
        /// <returns>The action result that will output the token response.</returns>
        [HttpPost]
        public ActionResult Index()
        {
            // Have the authorization server handle the token request. It will use the passed-in request
            // to determine what the actual token request is. If the request does not contain a valid
            // token request, an exception is thrown
            var outgoingWebResponse = this.authorizationServer.HandleTokenRequest(this.Request);

            // Convert the outgoing web response to an ActionResult to correctly integrate with ASP.NET MVC flow
            return outgoingWebResponse.AsActionResult();
        }
    }
}