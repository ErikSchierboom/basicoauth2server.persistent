namespace OAuth2Server.Models
{
    using System;
    using System.ComponentModel.DataAnnotations;

    public class Authorization
    {
        [Key]
        public virtual int Id { get; set; }

        [Required]
        public virtual DateTime IssueDate { get; set; }

        [Required]
        public virtual int ClientId { get; set; }
        public virtual Client Client { get; set; }

        [Required]
        public virtual int UserId { get; set; }
        public virtual User User { get; set; }

        public virtual string Scope { get; set; }
        
        public virtual DateTime? ExpirationDateUtc { get; set; }
    }
}