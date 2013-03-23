namespace OAuth2Server.ViewModels.Home
{
    using System.ComponentModel.DataAnnotations;

    public class RefreshTokenViewModel
    {
        [Required]
        public string RefreshToken { get; set; }

        [Required]
        public string ClientId { get; set; }

        [Required]
        public string ClientSecret { get; set; }
    }
}