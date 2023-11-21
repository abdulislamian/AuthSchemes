using AuthSchemesAndOptions.Extensions;
using AuthSchemesAndOptions.Repositories;
using JWTAuthentication.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthSchemesAndOptions.Repositories
{
    public class TokenRepository : ITokenRepository
    {
        private readonly ApplicationDbContext dbContext;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IHttpContextAccessor context;
        private readonly IConfiguration _configuration;
        private readonly JwtConfiguration _Jwtconfiguration;

        public TokenRepository(ApplicationDbContext _dbContext,
            UserManager<IdentityUser> _userManager,IHttpContextAccessor _context,IConfiguration configuration)
        {
            dbContext = _dbContext;
            userManager = _userManager;
            context = _context;
            _configuration = configuration;
            _Jwtconfiguration = new JwtConfiguration();
            _configuration.Bind(_Jwtconfiguration.Section, _Jwtconfiguration);
        }
        public string CreateJWTToken(IdentityUser user, List<string> roles)
        {
            //Create SomeClaims 
            var claims = new List<Claim>();

            claims.Add(new Claim(ClaimTypes.Email, user.Email));
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var Key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_Jwtconfiguration.Key));

            var credentials = new SigningCredentials(Key, SecurityAlgorithms.HmacSha256);

            var Token = new JwtSecurityToken(
                _Jwtconfiguration.Issuer,
                _Jwtconfiguration.Audience,
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(Token);
        }
    }
}
