namespace OAuth2Server.Models
{
    using System.Collections.Generic;

    public class User
    {
        public virtual int Id { get; set; }

        public virtual string OpenIDClaimedIdentifier { get; set; }

        public virtual string OpenIDFriendlyIdentifier { get; set; }

        public virtual ISet<Authorization> Authorizations { get; set; }
    }
}