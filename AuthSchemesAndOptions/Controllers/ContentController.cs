using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthSchemesAndOptions.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ContentController : ControllerBase
    {
        /// <summary>
        /// Access with Only Cookie Authentication
        /// </summary>
        /// <returns>Return Data with Cookie Authentication</returns>
        ///<response code="200">Successful Response for Authorized User</response>
        /// <response code="401">UnAuthorized Access</response>
        [Authorize(Policy = "OnlyCookieScheme")]
        [HttpGet("getWithCookie")]
        public IActionResult GetWithCookie()
        {
            var userName = HttpContext.User.Claims
                    .Where(x => x.Type == ClaimTypes.Name)
                    .Select(x => x.Value)
                    .FirstOrDefault();

            return Content($"<p>Hello to Code Maze {userName}</p>");
        }
    }
}
