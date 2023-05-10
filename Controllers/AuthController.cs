using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using mywebapi.Data;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace mywebapi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }


        [HttpPost("signup")]
        public async Task<IActionResult> SignUp([FromBody] SignUpRequest model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return BadRequest(ModelState);
            }

            var signInResult = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);

            if (!signInResult.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return BadRequest(ModelState);
            }

            var token = GenerateJwtToken(user);

            return Ok(new SignInResponse { Token = token });
        }


        [HttpPost("signin")]
        public async Task<IActionResult> SignIn(SignInRequest signInRequest)
        {
            var result = await _signInManager.PasswordSignInAsync(signInRequest.Email, signInRequest.Password, false, false);
            if (result.Succeeded)
            {
                // return Ok(new { Message = "User signed in successfully." });
                var user = await _signInManager.UserManager.FindByEmailAsync(signInRequest.Email);
                var token = GenerateJwtToken(user);
                return Ok(new SignInResponse { Token = token });
            }
            else
            {
                return BadRequest(new { Message = "Invalid username or password." });
            }
        }


        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpGet("whoami")]
        public async Task<IActionResult> WhoAmI()
        {
            // Get the user ID from the JWT token
            var userId = User.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;

            // Retrieve the user from the database
            var user = await _userManager.FindByIdAsync(userId);

            // Return the user information
            return Ok(new
            {
                Id = user.Id,
                Email = user.Email,
                // FirstName = user.FirstName,
                // LastName = user.LastName
            });
        }

        private string GenerateJwtToken(ApplicationUser user)
        {

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var jwtSection = _configuration.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddDays(int.Parse(jwtSection["TokenExpirationInMinutes"]));

            var token = new JwtSecurityToken(
                issuer: jwtSection["Issuer"],
                audience: jwtSection["Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }

    public class SignUpRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public class SignInRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class SignInResponse
    {
        public string Token { get; set; }
    }


}
