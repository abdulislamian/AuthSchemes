using Microsoft.AspNetCore.Identity;

namespace AuthSchemesAndOptions.Repositories
{
    public interface ITokenRepository
    {
        string CreateJWTToken(IdentityUser user, List<string> roles);
    }
}
