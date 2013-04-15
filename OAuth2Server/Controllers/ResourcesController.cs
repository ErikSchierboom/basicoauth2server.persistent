namespace OAuth2Server.Controllers
{
    using System.Web.Mvc;

    using OAuth2Server.Models;

    /// <summary>
    /// This controller will return resources, but only if the token provided is valid. The server uses the
    /// username/client identifier combination to determine which resource to allocate.
    /// </summary>
    [RequireHttps]
    public class ResourcesController : Controller
    {
        /// <summary>
        /// This action provides access to protected client resources. The <see cref="OAuthAuthorizeAttribute"/>
        /// applied to this action means that this action can only be called when the user calls it with a
        /// token that is granted the "demo-scope-client-1" scope (which is only issued to client #1).
        /// </summary>
        /// <returns>The action result that will output the token response.</returns>
        [HttpGet]
        [OAuthAuthorizeAttribute(Scopes = "demo-scope-client-1")]
        public ContentResult Clients()
        {
            return this.Content(string.Format("Protected resource of: {0}", this.HttpContext.User.Identity.Name));
        }

        /// <summary>
        /// This action provides access to protected user resources. The <see cref="OAuthAuthorizeAttribute"/>
        /// applied to this action means that this action can only be called when the user calls it with a
        /// token that is granted the "demo-scope-1" scope (which is only issued to user #1 and #2).
        /// </summary>
        /// <returns>The action result that will output the resource.</returns>
        [HttpGet]
        [OAuthAuthorizeAttribute(Scopes = "demo-scope-1")]
        public ContentResult Users()
        {
            return this.Content(string.Format("Protected resource of: {0}", this.HttpContext.User.Identity.Name));
        }
    }
}