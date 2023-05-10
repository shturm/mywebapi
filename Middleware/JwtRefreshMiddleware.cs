using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using mywebapi.Services;
using mywebapi.Data;

namespace mywebapi.Middleware
{
    public class JwtRefreshMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtRefreshMiddleware> _logger;

        public JwtRefreshMiddleware(RequestDelegate next, IConfiguration configuration, ILogger<JwtRefreshMiddleware> logger)
        {
            _next = next;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, IJwtService jwtService)
        {
            string token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
            {
                    try
                    {
                        ClaimsPrincipal tokenPrincipal = jwtService.GetPrincipalFromToken(token);
                        DateTime expirationDate = DateTime.Parse(tokenPrincipal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                        if (expirationDate <= DateTime.UtcNow.AddMinutes(5)) // Check if the token is about to expire
                        {
                            string userId = tokenPrincipal.Claims.Single(x => x.Type == "id").Value;
                            ApplicationUser user = await jwtService.FindUserByIdAsync(userId);

                            if (user != null && await jwtService.CheckPasswordAsync(user, user.PasswordHash)) // Validate the user and password
                            {
                                // Refresh the token
                                string newToken = jwtService.GenerateToken(user.Id.ToString());
                                context.Response.Headers.Add("Authorization", "Bearer " + newToken);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error refreshing JWT token");
                    }
            }

            await _next(context);
        }
    }

}