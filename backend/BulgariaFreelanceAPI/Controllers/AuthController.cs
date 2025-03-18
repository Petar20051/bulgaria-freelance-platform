using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using BulgariaFreelanceAPI.Services;

namespace BulgariaFreelanceAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;

        public AuthController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailSender = emailSender;
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                // Generate email confirmation token
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(
                    "ConfirmEmail",
                    "Auth",
                    new { userId = user.Id, token },
                    protocol: HttpContext.Request.Scheme);

                // Send confirmation email
                await _emailSender.SendEmailAsync(user.Email, "Confirm your email",
                    $"Please confirm your account by clicking <a href='{confirmationLink}'>here</a>.");

                return Ok(new { Message = "User registered successfully. Please check your email to confirm your account." });
            }
            return BadRequest(result.Errors);
        }

        // GET: api/auth/confirmemail?userId=...&token=...
        [HttpGet("confirmemail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
                return BadRequest("User ID and token are required.");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
                return Ok("Email confirmed successfully.");
            return BadRequest("Error confirming email.");
        }

        // POST: api/auth/resendconfirmation
        [HttpPost("resendconfirmation")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationModel model)
        {
            if (string.IsNullOrWhiteSpace(model.Email))
                return BadRequest("Email is required.");

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return NotFound("User not found.");
            if (await _userManager.IsEmailConfirmedAsync(user))
                return BadRequest("Email is already confirmed.");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(
                    "ConfirmEmail",
                    "Auth",
                    new { userId = user.Id, token },
                    protocol: HttpContext.Request.Scheme);

            await _emailSender.SendEmailAsync(user.Email, "Confirm your email",
                    $"Please confirm your account by clicking <a href='{confirmationLink}'>here</a>.");
            return Ok("Confirmation email resent. Please check your email.");
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Unauthorized("Invalid credentials.");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized("Email not confirmed.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!result.Succeeded)
                return Unauthorized("Invalid credentials.");

            var token = GenerateJwtToken(user);
            return Ok(new { Token = token });
        }

        // POST: api/auth/forgotpassword
        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
        {
            if (string.IsNullOrWhiteSpace(model.Email))
                return BadRequest("Email is required.");

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                return BadRequest("User does not exist or email is not confirmed.");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action(
                "ResetPassword",
                "Auth",
                new { email = user.Email, token },
                protocol: HttpContext.Request.Scheme);

            await _emailSender.SendEmailAsync(user.Email, "Reset your password",
                $"Please reset your password by clicking <a href='{resetLink}'>here</a>.");
            return Ok(new { Message = "Password reset link has been sent to your email." });
        }

        // POST: api/auth/resetpassword
        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("User does not exist.");

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
                return Ok("Password reset successfully.");
            return BadRequest(result.Errors);
        }

        // GET: api/auth/2fa/setup
        [Authorize]
        [HttpGet("2fa/setup")]
        public async Task<IActionResult> SetupTwoFactor()
        {
            // In a production implementation, you might generate a QR code for authenticator apps.
            // Here, we return the authenticator key.
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }
            return Ok(new { AuthenticatorKey = key, Message = "Use this key in your authenticator app." });
        }

        // POST: api/auth/2fa/verify
        [Authorize]
        [HttpPost("2fa/verify")]
        public async Task<IActionResult> VerifyTwoFactor([FromBody] VerifyTwoFactorModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if (isValid)
                return Ok("Two-factor authentication verified successfully.");
            return BadRequest("Invalid two-factor code.");
        }

        // GET: api/auth/profile
        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found.");

            return Ok(new { user.Email, user.UserName, user.TwoFactorEnabled });
        }

        // Helper method to generate JWT token
        private string GenerateJwtToken(IdentityUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    
    public record RegisterModel(string Email, string Password);
    public record LoginModel(string Email, string Password);
    public record ForgotPasswordModel(string Email);
    public record ResetPasswordModel(string Email, string Token, string NewPassword);
    public record TwoFactorEnableModel(string Email);
    public record ResendConfirmationModel(string Email);
    public record VerifyTwoFactorModel(string Code);
}
