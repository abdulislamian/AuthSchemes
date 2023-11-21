using AuthSchemesAndOptions.Models;
using Azure.Core;
using JWTAuthentication.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthSchemesAndOptions.Extensions
{
    public static class ServiceExtensions
    {
        public static void ConfigureIdentity(this IServiceCollection services)
        {
            var builder = services.AddIdentity<IdentityUser, IdentityRole>(o =>
            {
                o.Password.RequireDigit = true;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequiredLength = 6;
                o.User.RequireUniqueEmail = true;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        }
        public static void ConfigureAuthentication(this IServiceCollection services, IConfiguration
        configuration)
        {
            var jwtSettings = configuration.GetSection("JWT");
            var jwtConfiguration = new JwtConfiguration();
            configuration.Bind(jwtConfiguration.Section, jwtConfiguration);

            //var secretKey = Environment.GetEnvironmentVariable("Key");
            var secretKey = Encoding.UTF8.GetBytes(jwtConfiguration.Key);
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "MultiAuthSchemes";
                options.DefaultChallengeScheme = "MultiAuthSchemes";
                options.DefaultScheme = "MultiAuthSchemes";
            })
            .AddCookie(options =>
            {
                options.Events.OnRedirectToLogin = (context) =>
                {
                    context.Response.StatusCode = 401;
                    return Task.CompletedTask;
                };
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtConfiguration.Issuer,
                    ValidAudience = jwtConfiguration.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(secretKey)
                };
            })
            .AddJwtBearer("SecondJwtScheme", options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "https://localhost:7209/",
                    ValidAudience = jwtConfiguration.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@2"))
                };
            })
            .AddPolicyScheme("MultiAuthSchemes", JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    string authorization = context.Request.Headers[HeaderNames.Authorization];
                    var allCookies = context.Request.Cookies;
                    if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                    {
                        var token = authorization.Substring("Bearer ".Length).Trim();
                        var jwtHandler = new JwtSecurityTokenHandler();
                        var issuer = jwtHandler.ReadJwtToken(token).Issuer;
                        bool abc = jwtHandler.ReadJwtToken(token).Issuer.Equals(jwtConfiguration.Issuer);
                        return (jwtHandler.CanReadToken(token) && jwtHandler.ReadJwtToken(token).Issuer.Equals(jwtConfiguration.Issuer))
                            ? JwtBearerDefaults.AuthenticationScheme : "SecondJwtScheme";
                    }
                    return CookieAuthenticationDefaults.AuthenticationScheme;
                };
            });
        }
        public static void ConfigureAuthorization(this IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("OnlyAdmin", policy => policy.RequireRole("Admin").AddAuthenticationSchemes("MultiAuthSchemes"));
                options.AddPolicy("AllUser", policy => policy.RequireRole("Admin", "User").AddAuthenticationSchemes("MultiAuthSchemes"));

                var onlySecondJwtSchemePolicyBuilder = new AuthorizationPolicyBuilder("SecondJwtScheme");
                options.AddPolicy("OnlySecondJwtScheme", onlySecondJwtSchemePolicyBuilder
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("SecondJwtScheme")
                    .Build());

                var onlyCookieSchemePolicyBuilder = new AuthorizationPolicyBuilder(CookieAuthenticationDefaults.AuthenticationScheme);
                options.AddPolicy("OnlyCookieScheme", onlyCookieSchemePolicyBuilder
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
                    .Build());


            });
        }
    }
}
