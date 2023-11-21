using AuthSchemesAndOptions.Models;
using JWTAuthentication.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthSchemesAndOptions.Repositories
{
    public class SQLStudentRepository : IStudentRepository
    {
        private readonly ApplicationDbContext dbContext;

        public SQLStudentRepository(ApplicationDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public async Task<Student> CreateAsync(Student student)
        {
            await dbContext.Students.AddAsync(student);
            await dbContext.SaveChangesAsync();
            return student;
        }

        public async Task<List<Student>> GetAllAsync()
        {
            return await dbContext.Students.ToListAsync();
        }
    }
}
