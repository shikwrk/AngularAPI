using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Data.SqlClient;
using AngularAPI.Models;
using AngularAPI.Models.DTOs;
using AngularAPI.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
namespace AngularAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MemberController : ControllerBase
    {
        private readonly ILogger<AuthManagementController> _logger;
        private IConfiguration _config;
        private readonly JwtConfig _jwtConfig;
        private readonly IPasswordHasher<UserRegistrationRequestDTO> _passwordHasher;

        public MemberController(ILogger<AuthManagementController> logger, IConfiguration config, IOptionsMonitor<JwtConfig> optionsMonitor, IPasswordHasher<UserRegistrationRequestDTO> passwordHasher)
        {
            _logger = logger;
            _config = config;
            _jwtConfig = optionsMonitor.CurrentValue;
            _passwordHasher = passwordHasher;
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO requestDTO)
        {
            if (ModelState.IsValid)
            {
                string query = "SELECT * FROM dbo.tMembers WHERE Email = @Email";
                string sqlDatasource = _config.GetConnectionString("AngularDBCon");

                using (SqlConnection myCon = new SqlConnection(sqlDatasource))
                {
                    myCon.Open();
                    using (SqlCommand myCommand = new SqlCommand(query, myCon))
                    {
                        myCommand.Parameters.AddWithValue("@Email", requestDTO.Email);
                        using (SqlDataReader myReader = myCommand.ExecuteReader())
                        {
                            if (myReader.Read())
                            {
                                string storedPasswordHash = myReader["PasswordHash"].ToString();
                                bool isPasswordMatch = VerifyPasswordHash(requestDTO.Password, storedPasswordHash);
                                if (isPasswordMatch)
                                {
                                    TMember member = new TMember();
                                    member.Id = Convert.ToInt32(myReader["Id"]);
                                    member.Email = myReader["Email"].ToString();
                                    member.Name = myReader["Name"].ToString();

                                    var token = GenerateJwtToken(member);

                                    var response = new LoginRequestResponse()
                                    {
                                        Result = true,
                                        Token = token,
                                        Id = member.Id.ToString(),
                                        Email = member.Email,
                                        Name = member.Name
                                    };

                                    return Ok(response); 
                                }
                                else
                                {
                                    return BadRequest("Incorrect password.");
                                }
                            }
                            else
                            {
                                return BadRequest("User not found.");
                            }
                        }
                    }
                }
            }
            else
            {
                return BadRequest("Invalid request payload");
            }
        }

        [HttpPost]
        [Route("Register")]
        public IActionResult CreateMember([FromBody] UserRegistrationRequestDTO member )
        {
            if (member == null || string.IsNullOrEmpty(member.Email) || string.IsNullOrEmpty(member.Password))
            {
                return BadRequest("Member information is not complete.");
            }

            string query = "INSERT INTO dbo.tMembers (Name, Email, PasswordHash) VALUES (@Name, @Email, @PasswordHash)";

            string sqlDS = _config.GetConnectionString("AngularDBCon");

            using (SqlConnection myCon = new SqlConnection(sqlDS))
            {
                myCon.Open();
                using (SqlCommand myCommand = new SqlCommand(query, myCon))
                {
                    string hashedPassword = _passwordHasher.HashPassword(member, member.Password);
                    myCommand.Parameters.AddWithValue("@Name", member.Name);
                    myCommand.Parameters.AddWithValue("@Email", member.Email);
                    myCommand.Parameters.AddWithValue("@PasswordHash", hashedPassword);

                    int rowsAffected = myCommand.ExecuteNonQuery();
                    if (rowsAffected > 0)
                    {
                        return Ok(new { Message = "Created Successfully" });
                    }
                    else
                    {
                        return BadRequest("Failed to create member.");
                    }
                }
            }
        }

        private string GenerateJwtToken(TMember member)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", member.Id.ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, member.Email),
                    new Claim(JwtRegisteredClaimNames.Name, member.Name),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(4),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            return jwtToken;
        }

        private bool VerifyPasswordHash(string providedPassword, string storedHash)
        {
            var hasher = new PasswordHasher<IdentityUser>();
            var result = hasher.VerifyHashedPassword(new IdentityUser(), storedHash, providedPassword);
            return result == PasswordVerificationResult.Success;
        }
    }
}
