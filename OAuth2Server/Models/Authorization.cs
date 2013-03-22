namespace OAuth2Server.Models
{
    using System;

    public class Authorization
    {
        public virtual int Id { get; set; }

        public virtual DateTime IssueDate { get; set; }

        public virtual int ClientId { get; set; }
        public virtual Client Client { get; set; }

        public virtual int UserId { get; set; }
        public virtual User User { get; set; }

        public virtual string Scope { get; set; }

        public virtual DateTime? ExpirationDateUtc { get; set; }
    }
}