namespace OAuth2Server.Models
{
    using System.Data.Entity;

    /// <summary>
    /// This class is used to initialize the database whenever the model changes.
    /// We use this class to automatically seed the database with default values.
    /// </summary>
    public class OAuth2ServerDbContextInitializer : DropCreateDatabaseIfModelChanges<OAuth2ServerDbContext>
    {
        protected override void Seed(OAuth2ServerDbContext context)
        {
            base.Seed(context);

            // Define our default clients
            var client1 = new Client { Name = "Demo Client 1", ClientIdentifier = "demo-client-1", ClientSecret = "demo-client-secret-1" };
            var client2 = new Client { Name = "Demo Client 2", ClientIdentifier = "demo-client-2", ClientSecret = "demo-client-secret-2" };

            // Define our default users
            var user1 = new User { OpenIDClaimedIdentifier = "demo-user-1", OpenIDFriendlyIdentifier = "demo-user-1" };
            var user2 = new User { OpenIDClaimedIdentifier = "demo-user-2", OpenIDFriendlyIdentifier = "demo-user-2" };
            
            // Add the clients
            context.Clients.Add(client1);
            context.Clients.Add(client2);

            // Add the users
            context.Users.Add(user1);
            context.Users.Add(user1);

            // Store the clients and users we added, effectively seeding the database
            context.SaveChanges();
        }
    }
}