using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AccountApi
{
    public class JWTService
    {
        private readonly IConfiguration _configuration;

        public JWTService(IConfiguration configuration)
        {
            _configuration = configuration;
        }


		public Token GetToken(string userId,int minutes)
		{
			try
			{
				var tokenHandler = new JwtSecurityTokenHandler();
				var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
				var tokenDescriptor = new SecurityTokenDescriptor
				{
					Subject = new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Name, userId) }),
					Expires = DateTime.Now.AddMinutes(minutes),
					SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
				};

				var accessToken = tokenHandler.CreateToken(tokenDescriptor);
				var refreshToken = GetRefreshToken();

				Token token = new Token
				{
					AccessToken = tokenHandler.WriteToken(accessToken),
					RefreshToken = refreshToken
				};

				return token;
			}
			catch
			{
				return null;
			}
		}

		private string GetRefreshToken()
        {
			var randomNumber = new byte[32];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(randomNumber);
				return Convert.ToBase64String(randomNumber);
			}
		}


		public ClaimsPrincipal GetClaimsFromExpiredToken(string accessToken)
		{
			var Key = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);

			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateIssuer = false,
				ValidateAudience = false,
				ValidateLifetime = false,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Key),
				ClockSkew = TimeSpan.Zero
			};

			var tokenHandler = new JwtSecurityTokenHandler();

			var claims = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

			JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;

			if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
			{
				throw new SecurityTokenException("Invalid token");
			}


			return claims;
		}
	}
}
