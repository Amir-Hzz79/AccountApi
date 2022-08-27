using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AccountApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class AccountApi : ControllerBase
    {
        private readonly ApiDbContext _context;
        private readonly JWTService _jWTService;

        public AccountApi(ApiDbContext context , JWTService jWTService)
        {
            _context = context;
            _jWTService = jWTService;
        }

        [HttpPost]
        [Route("GenerateToken")]
        public IActionResult GenerateToken([FromQuery]User user)
        {
            if (ModelState.IsValid)
            {
                User dbUser=_context.Users.FirstOrDefault(u => u.Username == user.Username && u.Password == user.Password);

                if (dbUser == null)
                {
                    return BadRequest("Username and password not found!!");
                }

                int minute = 2;
                Token token = _jWTService.GetToken(dbUser.Id.ToString(), minute);

                return Ok(token);
            }

            return BadRequest("Not valid user");
        }

        [Authorize]
        [HttpPost]
        [Route("RefreshToken")]
        public IActionResult GenerateRefreshToken([FromQuery]Token oldToken)
        {
            if (ModelState.IsValid)
            {
                var claims = _jWTService.GetClaimsFromExpiredToken
                    (oldToken.AccessToken);
                if (claims == null)
                    return BadRequest("Unvalid token");

                string userId = claims.Identity.Name;
                if (userId == null)
                    return BadRequest("Unvalid token");


                User user = _context.Users.Find(Convert.ToInt32(userId));
                if (user == null)
                    return BadRequest("Unvalid token");


                int minute = 2;
                Token newToken = _jWTService.GetToken(user.Id.ToString(), minute);

                return Ok(newToken);
            }

            return BadRequest("Unvalid token");
        }
    }
}
