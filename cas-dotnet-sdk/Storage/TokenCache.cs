

using CASHelpers;
using CASHelpers.Types.HttpResponses.UserAuthentication;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CasDotnetSdk.Storage
{
    internal class TokenCache
    {
        internal string Token { get; set; }
        public DateTime TokenExpiresIn { get; set; }
        private Timer Timer { get; set; }
        private int TimerInterval { get; set; }
        internal string StripProductLicenseSignature { get; set; }
        internal string ProductLicensePublicKey { get; set; }

        public TokenCache()
        {
            this.TimerInterval = 15;
        }

        public async Task<string> GetTokenAfterApiKeySet(string apiKey)
        {
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + Constants.ApiRoutes.Token;
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.ApiKey, apiKey);
            HttpResponseMessage response = await httpClient.GetAsync(url);
            if (!response.IsSuccessStatusCode && response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return null;
            }
            JsonSerializerOptions options = new JsonSerializerOptions()
            {
                PropertyNameCaseInsensitive = true,
            };
            GetTokenResponse tokenResponse = JsonSerializer.Deserialize<GetTokenResponse>(await response.Content.ReadAsStringAsync(), options);
            this.Token = tokenResponse.Token;
            this.Timer = new Timer(GetRefreshToken, null, TimeSpan.FromSeconds(this.TimerInterval), TimeSpan.FromSeconds(this.TimerInterval));
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken parsedToken = tokenHandler.ReadJwtToken(this.Token);
            this.TokenExpiresIn = parsedToken.ValidTo;
            return apiKey;
        }

        private async void GetRefreshToken(object state)
        {
            if (DateTime.UtcNow.AddMinutes(5) >= this.TokenExpiresIn)
            {
                HttpClientSingleton httpClient = HttpClientSingleton.Instance;
                string url = CASConfiguration.Url + Constants.ApiRoutes.Token + Constants.ApiRoutes.RefreshToken;
                httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, this.Token);
                HttpResponseMessage response = await httpClient.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    JsonSerializerOptions options = new JsonSerializerOptions()
                    {
                        PropertyNameCaseInsensitive = true,
                    };
                    GetTokenResponse tokenResponse = JsonSerializer.Deserialize<GetTokenResponse>(await response.Content.ReadAsStringAsync(), options);
                    this.Token = tokenResponse.Token;
                    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                    JwtSecurityToken parsedToken = tokenHandler.ReadJwtToken(this.Token);
                    this.TokenExpiresIn = parsedToken.ValidTo;
                }
            }
        }
    }
}
