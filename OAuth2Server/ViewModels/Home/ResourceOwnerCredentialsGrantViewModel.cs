namespace OAuth2Server.ViewModels.Home
{
    using System.ComponentModel.DataAnnotations;

    public class ResourceOwnerCredentialsGrantViewModel
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        public string ClientId { get; set; }

        public string Scope { get; set; }
    }
}