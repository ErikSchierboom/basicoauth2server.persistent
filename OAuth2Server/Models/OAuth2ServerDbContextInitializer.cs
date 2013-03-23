namespace OAuth2Server.Models
{
    using System;
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
            var client1 = new Client { Name = "Demo Client 1", ClientIdentifier = "demo-client-1", ClientSecret = "demo-client-secret-1", Scope = "demo-scope-client-1" };
            var client2 = new Client { Name = "Demo Client 2", ClientIdentifier = "demo-client-2", ClientSecret = "demo-client-secret-2", Scope = "demo-scope-client-2" };

            // Define our default users
            var user1 = new User { OpenIDClaimedIdentifier = "demo-user-1", OpenIDFriendlyIdentifier = "demo-user-1", Password = "demo-user-password-1" };
            var user2 = new User { OpenIDClaimedIdentifier = "demo-user-2", OpenIDFriendlyIdentifier = "demo-user-2", Password = "demo-user-password-2" };
            
            // Add the clients
            context.Clients.Add(client1);
            context.Clients.Add(client2);

            // Add the users
            context.Users.Add(user1);
            context.Users.Add(user2);

            // Store the clients and users we added, effectively seeding the database
            context.SaveChanges();

            // Add the authorizations to the users
            user1.Authorizations.Add(new Authorization { ClientId = client1.Id, UserId = user1.Id, ExpirationDateUtc = DateTime.Now.AddHours(1), IssueDate = DateTime.Now.AddHours(-1), Scope = "demo-scope-1" });
            user1.Authorizations.Add(new Authorization { ClientId = client2.Id, UserId = user1.Id, ExpirationDateUtc = null, IssueDate = DateTime.Now.AddHours(-2), Scope = "demo-scope-1 demo-scope-2" });
            user2.Authorizations.Add(new Authorization { ClientId = client1.Id, UserId = user2.Id, ExpirationDateUtc = DateTime.Now.AddHours(-5), IssueDate = DateTime.Now.AddHours(-6), Scope = "demo-scope-1" });

            // Store the authorizations
            context.SaveChanges();
        }
    }
}