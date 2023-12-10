using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CasDotnetSdk
{
    public class JWT
    {
        public async Task<bool> ValidateECCToken(string token, ECDsa publicKey)
        {
            JsonWebTokenHandler newHandler = new JsonWebTokenHandler();
            TokenValidationResult result = await newHandler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidIssuer = "https://encryptionapiservices.com",
                IssuerSigningKey = new ECDsaSecurityKey(publicKey)
            });
            return result.IsValid;
        }
        public string GetUserIdFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler().ReadJwtToken(token);
            return handler.Claims.First(x => x.Type == "id").Value;
        }
    }
}