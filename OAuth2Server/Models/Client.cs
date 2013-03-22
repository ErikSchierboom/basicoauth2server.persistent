namespace OAuth2Server.Models
{
    using System;
    using System.Collections.Generic;

    using DotNetOpenAuth.OAuth2;

    public class Client
    {
        public virtual int Id { get; set; }

        public virtual string ClientIdentifier { get; set; }

        public virtual string ClientSecret { get; set; }

        public virtual Uri Callback { get; set; }

        public virtual string Name { get; set; }

        public virtual ClientType ClientType { get; set; }

        public virtual ISet<Authorization> Authorizations { get; set; }
    }
}