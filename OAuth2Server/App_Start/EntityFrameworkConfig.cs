namespace OAuth2Server.App_Start
{
    using System.Data.Entity;

    using OAuth2Server.Models;

    /// <summary>
    /// Configure Entity Framework.
    /// </summary>
    public class EntityFrameworkConfig
    {
        public static void Config()
        {
            // Use our own database initializer
            Database.SetInitializer(new OAuth2ServerDbContextInitializer());
        }
    }
}