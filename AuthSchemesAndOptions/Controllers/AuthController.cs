using AuthSchemesAndOptions.Models.DTO;
using AuthSchemesAndOptions.Repositories;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthSchemesAndOptions.Models;
using AuthSchemesAndOptions.Extensions;

namespace AuthSchemesAndOptions.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ITokenRepository tokenRepository;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration configuration;
        private readonly JwtConfiguration _Jwtconfiguration;

        public AuthController(UserManager<IdentityUser> userManager, ITokenRepository _tokenRepository, SignInManager<IdentityUser> signInManager,
           IConfiguration _configuration)
        {
            _userManager = userManager;
            tokenRepository = _tokenRepository;
            _signInManager = signInManager;
            configuration = _configuration;
            _Jwtconfiguration = new JwtConfiguration();
            _configuration.Bind(_Jwtconfiguration.Section, _Jwtconfiguration);
        }


        #region RegisterUser
        //POST :  /api/Auth/Register
        /// <summary>
        /// Create New User (Only Accessed by Admin)
        /// </summary>
        /// <returns>Return Newly Created User</returns>
        [HttpPost]
        [Route("Register")]
        [Authorize(policy: "OnlyAdmin")]
        [ProducesResponseType(201)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDTO registerRequestDTO)
        {
            var identityUser = new IdentityUser
            {
                UserName = registerRequestDTO.Username,
                Email = registerRequestDTO.Username
            };
            var identityResult = await _userManager.CreateAsync(identityUser, registerRequestDTO.Password);
            if (identityResult.Succeeded)
            {
                //Add roles  to this User
                if (registerRequestDTO.Roles != null && registerRequestDTO.Roles.Any())
                {
                    identityResult = await _userManager.AddToRolesAsync(identityUser, registerRequestDTO.Roles);

                    if (identityResult.Succeeded)
                    {
                        return Ok("User was Registed! Please Login");
                    }
                }

            }
            else
            {
                List<string> errorlist = new List<string>();
                foreach (var error in identityResult.Errors)
                {
                    errorlist.Add(error.Description);
                }

                return BadRequest(errorlist);
            }
            return BadRequest("Something went Wrong.");

        }
        #endregion

        /// <summary>
        /// Login With DefaultJWT
        /// </summary>
        /// <returns>Return Token by DefaultJWT</returns>
        /// <response code="200">Returns JWT Token</response>
        /// <response code="401">UnAuthorized Access</response>
        #region Login
        [HttpPost("loginDefaultJwt")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> LoginDefaultJwt([FromBody] LoginRequestDTO loginRequestDTO)
        {
            var IsUserExist = await _userManager.FindByEmailAsync(loginRequestDTO.Username);
            if (IsUserExist != null)
            {
                var login = await _signInManager.CheckPasswordSignInAsync(IsUserExist, loginRequestDTO.Password, true);

                if (login.Succeeded)
                {
                    var roles = await _userManager.GetRolesAsync(IsUserExist);
                    if (roles != null)
                    {
                        //Create Token
                        var JWTToken = tokenRepository.CreateJWTToken(IsUserExist, roles.ToList());

                        var response = new LoginResponseDTO
                        {
                            JwtToken = JWTToken
                        };
                        return Ok(response);
                    }

                    return Ok("Login Successful");
                }
                if (login.IsLockedOut)
                {
                    return BadRequest("Your account is Lockout for 15mins due to invalid attempts");
                }
            }
            return BadRequest("Username or Password is incorrect.");
        }

        /// <summary>
        /// Login With SecondJWT
        /// </summary>
        /// <returns>Return Token by SecondJWT</returns>
        /// <response code="200">Returns SecondJWT Token</response>
        /// <response code="401">UnAuthorized Access</response>
        [HttpPost("loginSecondJwt")]
        [ProducesResponseType(201)]
        [ProducesResponseType(400)]
        public IActionResult LoginSecondJwt([FromBody] User user)
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@2"));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var tokenOptions = new JwtSecurityToken(
                issuer: "https://localhost:7209/",
                audience: _Jwtconfiguration.Audience,
                claims: new List<Claim>() { new Claim(ClaimTypes.Name, user.Username ?? string.Empty), new Claim(ClaimTypes.Role, "User") },
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: signinCredentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

            return Ok(new { Token = tokenString });
        }

        /// <summary>
        /// Login With Cookie
        /// </summary>
        /// <returns>Return Cookie by Login</returns>
        /// <response code="200">Returns Cookie in Browser</response>
        /// <response code="401">UnAuthorized Access</response>
        [HttpPost("loginCookie")]
        [ProducesResponseType(201)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> LoginCookie([FromBody] LoginRequestDTO loginRequestDTO)
        {
            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
            identity.AddClaims(new[]
            {
                new Claim(ClaimTypes.Name, loginRequestDTO.Username ?? string.Empty),
                new Claim(ClaimTypes.Role, "User")
            });

            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    AllowRefresh = true,
                    ExpiresUtc = DateTime.UtcNow.AddDays(1)
                });
            return Ok();
        }
        #endregion
    }
}
