using AuthSchemesAndOptions.Models;
using AuthSchemesAndOptions.Models.DTO;
using AuthSchemesAndOptions.Repositories;
using AutoMapper;
using JWTAuthentication.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthSchemesAndOptions.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentController : ControllerBase
    {
        private readonly ApplicationDbContext dbContext;
        private readonly IStudentRepository studentRepository;
        private readonly IMapper mapper;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ITokenRepository tokenRepository;
        private readonly IHttpContextAccessor httpContextAccessor;

        public StudentController(ApplicationDbContext dbContext, IStudentRepository studentRepository, IMapper mapper,
            UserManager<IdentityUser> userManager, ITokenRepository tokenRepository,IHttpContextAccessor _httpContextAccessor)
        {
            this.dbContext = dbContext;
            this.studentRepository = studentRepository;
            this.mapper = mapper;
            _userManager = userManager;
            this.tokenRepository = tokenRepository;
            httpContextAccessor = _httpContextAccessor;
        }

        #region GellAllStudent
        /// <summary>
        /// Gets the list of all students
        /// </summary>
        /// <returns>The students list</returns>
        ///<response code="200">Successful Response for Authorized User</response>
        /// <response code="401">UnAuthorized Access</response>
        [HttpGet]
        [Authorize(Policy = "AllUser")]
        public async Task<IActionResult> GetAll()
        {
            var students = await studentRepository.GetAllAsync();

            //Populate DTO with Domain Model (Student)
            var studentDTO = mapper.Map<List<StudentDTO>>(students);

            return Ok(studentDTO);
        }
        #endregion

        #region CreateStudent
        //POST
        /// <summary>
        /// Create New student
        /// </summary>
        /// <returns>Return New Created Student</returns>
        [HttpPost]
        //[ValidateModel]
        [Authorize(Policy = "OnlyAdmin")]
        public async Task<IActionResult> Create([FromBody] AddStudentRequestDto AddStudentRequestDto)
        {
            var studentDomainModel = mapper.Map<Student>(AddStudentRequestDto);

            //Use Domain Model to create Region
            studentDomainModel = await studentRepository.CreateAsync(studentDomainModel);

            //Convert Back Region to regionDTO
            var studentDTO = mapper.Map<StudentDTO>(studentDomainModel);

            return Ok(studentDTO);
        }
        #endregion

        /// <summary>
        /// Get Data with First Default JWT
        /// </summary>
        /// <returns>Return First Default JWT</returns>
        /// <response code="200">Successful Response for Authorized User</response>
        /// <response code="401">UnAuthorized Access</response>
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] // Use default JWT scheme
        [HttpGet("getWithJWT")]
        public IActionResult GetWithJWT()
        {
            return Ok(new { Message = $"Hello to Code Maze {GetUsername()} - Only JWT Method" });
        }

        /// <summary>
        /// Get Data with Any Authentication Schemes
        /// </summary>
        /// <returns>Return Data with Any Authentication Schemes</returns>
        /// <response code="200">Successful Response for Authorized User</response>
        /// <response code="401">UnAuthorized Access</response>
        [Authorize]
        [HttpGet("getWithAny")]
        public IActionResult GetWithAny()
        {
            return Ok(new { Message = $"Hello to Code Maze {GetUsername()} - Access by Any Scheme" });
        }
        //[Authorize(Policy = "OnlySecondJwtScheme")]

        /// <summary>
        /// Get Data with SecondJWT Authentication Schemes
        /// </summary>
        /// <returns>Return Data with SecondJWT Authentication Schemes</returns>
        /// <response code="200">Successful Response for Authorized User</response>
        /// <response code="401">UnAuthorized Access</response>
        [Authorize(AuthenticationSchemes = "SecondJwtScheme")]
        [HttpGet("getWithSecondJwt")]
        public IActionResult GetWithSecondJwt()
        {
            return Ok(new { Message = $"Hello to Code Maze {GetUsername()} - Access with Second JWT" });
        }
        private string? GetUsername()
        {
            return HttpContext.User.Claims
                .Where(x => x.Type == ClaimTypes.Email)
                .Select(x => x.Value)
                .FirstOrDefault();
        }
    }
}
