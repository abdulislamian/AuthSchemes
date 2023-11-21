using AuthSchemesAndOptions.Models;

namespace AuthSchemesAndOptions.Repositories
{
    public interface IStudentRepository
    {
       Task<List<Student>> GetAllAsync();
       Task<Student> CreateAsync(Student student);
    }
}
