namespace OAuth2Server.App_Start
{
    using System.Data.Entity;

    using OAuth2Server.Models;

    public class EntityFrameworkConfig
    {
        public static void Config()
        {
            Database.SetInitializer(new OAuth2ServerDbContextInitializer());
        }
    }
}