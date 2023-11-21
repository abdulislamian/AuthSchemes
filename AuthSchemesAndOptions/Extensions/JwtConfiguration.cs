namespace AuthSchemesAndOptions.Extensions
{
    public class JwtConfiguration
    {
        public string Section {get;} = "JWT";
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public string? Expires { get; set; }
        public string? Key { get; set; }

    }
}
