namespace OAuth2Server
{
    using System.Web;
    using System.Web.Routing;

    using OAuth2Server.App_Start;

    public class MvcApplication : HttpApplication
    {
        protected void Application_Start()
        {
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }
    }
}