namespace AngularAPI.Models.DTOs
{
    public class LoginRequestResponse : AuthResult
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
    }
}
