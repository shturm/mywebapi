using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using mywebapi.Data;

namespace mywebapi.Services
{
    public interface IJwtService
    {
        ClaimsPrincipal GetPrincipalFromToken(string token);
        bool ValidateToken(string token, out string userId);
        string GenerateToken(string userId);
        Task<ApplicationUser> FindUserByIdAsync(string id);
        Task<bool> CheckPasswordAsync(ApplicationUser user, string passwordHash);

    }

    public class JwtService : IJwtService
    {
        private readonly string _secret;
        private readonly int _expiryInMinutes;
        private readonly UserManager<ApplicationUser> _userManager;

        public JwtService(IConfiguration config, UserManager<ApplicationUser> usermanager)
        {
            _secret = config["JwtSettings:SecretKey"];
            _expiryInMinutes = int.Parse(config["JwtSettings:TokenExpirationInMinutes"]);
            _userManager = usermanager;
        }

        public Task<ApplicationUser> FindUserByIdAsync(string id)
        {
            return _userManager.FindByIdAsync(id);
        }

        public string GenerateToken(string userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("userId", userId) }),
                Expires = DateTime.UtcNow.AddMinutes(_expiryInMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public bool ValidateToken(string token, out string userId)
        {
            userId = null;
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                userId = jwtToken.Claims.First(x => x.Type == "userId").Value;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
                if (!IsJwtWithValidSecurityAlgorithm(validatedToken))
                {
                    return null;
                }

                return principal;
            }
            catch
            {
                // Return null if token validation fails
                return null;
            }
        }
        public Task<bool> CheckPasswordAsync(ApplicationUser user, string passwordHash)
        {
            return _userManager.CheckPasswordAsync(user, passwordHash);
        }

        private TokenValidationParameters GetValidationParameters()
        {
            var secret = Encoding.ASCII.GetBytes(_secret);
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secret),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            };
        }

        private bool IsJwtWithValidSecurityAlgorithm(SecurityToken validatedToken)
        {
            return (validatedToken is JwtSecurityToken jwtSecurityToken)
                && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
        }

    }

}