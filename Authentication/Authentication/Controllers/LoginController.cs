using Microsoft.AspNetCore.Mvc;
using Authentication.Models;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _config;
        private static readonly TimeSpan TokenLifetime = TimeSpan.FromSeconds(30);

        public LoginController(IConfiguration configuration)
        { 
            _config= configuration;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(User user)
        {
            IActionResult response = Unauthorized();
            var _user = AuthenticateUser(user);
            if (_user != null)
            {
                var token = GenerateToken(_user);
                response = Ok(new { token = token });
            }
            return response;
        }

        private User AuthenticateUser(User user)
        {
            User _user = null;
            if (user.Username == "admin" && user.Password == "abc")
            {
                _user = new User { Username = "Bharani" };
            }
            return _user;

        }

        private string GenerateToken(User user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"], _config["Jwt:Audience"],null,
                expires: DateTime.UtcNow.Add(TokenLifetime),
                signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
