using AuthSchemesAndOptions.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Data;
using System.Reflection.Emit;

namespace JWTAuthentication.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<Student> Students { get; set; }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            var AdminId = "7eb3cc43-4661-47c7-ab04-c4e2b2693e56";
            var UserId = "bd1c7750-7cf5-4a51-9e0e-35181826d11d";

            var roles = new List<IdentityRole>
            {
                new IdentityRole()
                {
                    Id =AdminId,
                    ConcurrencyStamp=AdminId,
                    Name ="Admin",
                    NormalizedName = "Admin".ToUpper()
                },
                new IdentityRole()
                {
                    Id =UserId,
                    ConcurrencyStamp=UserId,
                    Name ="User",
                    NormalizedName = "User".ToUpper()
                }
            };

            builder.Entity<IdentityRole>().HasData(roles);

            SeedUsers(builder);
        }

        private void SeedUsers(ModelBuilder builder)
        {
            var hasher = new PasswordHasher<IdentityUser>();

            var SeedUser = new IdentityUser()
            {
                Id = "bd9a89a8-4047-45aa-9cbd-871062a30ab4",
                UserName = "Admin@gmail.com",
                Email = "ADMIN@GMAIL.COM",
                NormalizedUserName = "ADMIN@GMAIL.COM",
                PasswordHash = hasher.HashPassword(null, "Peshawar1@")
            };
            builder.Entity<IdentityUser>().HasData(SeedUser);

            var AsignRolesToUser = new List<IdentityUserRole<string>>
            {
                new IdentityUserRole<string>
                {
                    RoleId = "7eb3cc43-4661-47c7-ab04-c4e2b2693e56",
                    UserId = "bd9a89a8-4047-45aa-9cbd-871062a30ab4"
                }
            };

            builder.Entity<IdentityUserRole<string>>().HasData(AsignRolesToUser);
        }
    }
}
