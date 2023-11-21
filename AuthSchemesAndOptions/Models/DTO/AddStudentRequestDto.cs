using System.ComponentModel.DataAnnotations;

namespace AuthSchemesAndOptions.Models.DTO
{
    public class AddStudentRequestDto
    {
        [Required]
        public string Name { get; set; }
        public string Address { get; set; }
    }
}
