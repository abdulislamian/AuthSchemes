using AuthSchemesAndOptions.Models;
using AuthSchemesAndOptions.Models.DTO;
using AutoMapper;

namespace AuthSchemesAndOptions.Mappings
{
    public class AutoMapperProfiles : Profile
    {
        public AutoMapperProfiles()
        {
            CreateMap<Student, StudentDTO>().ReverseMap();
            CreateMap<AddStudentRequestDto,Student>().ReverseMap();
        }
    }
}
