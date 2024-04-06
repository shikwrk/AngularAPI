using AngularAPI.Configurations;
using AngularAPI.Models.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace AngularAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthManagementController :ControllerBase
    {

        private readonly ILogger<AuthManagementController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly IPasswordHasher<MemberDTO> _passwordHasher;

        public AuthManagementController(ILogger<AuthManagementController> logger,UserManager<IdentityUser>userManager,IOptionsMonitor<JwtConfig> optionsMonitor, IPasswordHasher<MemberDTO> passwordHasher)
        {
            _logger = logger;
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _passwordHasher = passwordHasher;
        }

        [HttpPost]
        [Route("Register2")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDTO requestDTO)
        {
            if (ModelState.IsValid)
            {
                var emailExist = await _userManager.FindByEmailAsync(requestDTO.Email);

                if(emailExist != null)
                {
                    return BadRequest("email already exist");
                }
                var newUser = new IdentityUser()
                {
                    Email = requestDTO.Email,
                    UserName = requestDTO.Name
                };

                var isCreated = await _userManager.CreateAsync(newUser, requestDTO.Password);
                if (isCreated.Succeeded)
                {
                    var token = GenerateJwtToken(newUser);

                    return Ok(new RegistrationRequestResponse()
                    {
                        Result = true,
                        Token = token
                    }); ;
                }
                return BadRequest(isCreated.Errors.Select(x=>x.Description).ToList());
            }
            return BadRequest("Invalid request payload");
        }

        [HttpPost]
        [Route("Login2")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO requestDTO)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(requestDTO.Email);

                if(existingUser == null)
                {
                    return BadRequest("Invalid authentication");
                }

                var isPasswordValid = await _userManager.CheckPasswordAsync(existingUser, requestDTO.Password);

                if (isPasswordValid)
                {
                    var token = GenerateJwtToken(existingUser);

                    //設置 HttpOnly Cookie
                    var cookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict,
                        Expires = DateTime.UtcNow.AddHours(4)  // 讓Cookie有效期限與Token一致
                    };

                    Response.Cookies.Append("jwtToken", token, cookieOptions);

                    return Ok(new LoginRequestResponse()
                    {
                        Result = true,
                        Token = token,
                        Id = existingUser.Id,
                        Name = existingUser.UserName,
                        Email = existingUser.Email
                    });
                }
                return BadRequest("Invalid authentication");
            }
            return BadRequest("Invalid request payload");
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(4),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            return jwtToken;
        }

        [HttpGet]
        [Route("MemberInfo2")]
        [Authorize]
        public IActionResult GetMemberInfo()
        {
            // 获取用户的 ID、Email 和名字
            var userId = User.Claims.FirstOrDefault(c => c.Type == "Id")?.Value;
            var email = User.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value;
            var name = User.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Name)?.Value;

            if (userId == null || email == null || name == null)
            {
                return NotFound();
            }

            return Ok(new { UserId = userId, Email = email, Name = name });
        }

    }
}
