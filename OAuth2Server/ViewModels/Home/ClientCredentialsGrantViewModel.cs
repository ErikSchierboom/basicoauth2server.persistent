namespace OAuth2Server.ViewModels.Home
{
    using System.ComponentModel.DataAnnotations;

    public class ClientCredentialsGrantViewModel
    {
        [Required]
        public string ClientId { get; set; }

        [Required]
        public string ClientSecret { get; set; }

        public string Scope { get; set; }
    }
}