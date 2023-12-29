using CasDotnetSdk.Types.ApiRequests;
using CASHelpers;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CasDotnetSdk
{
    public static class CASConfiguration
    {
        private static string _ApiKey;

        public static string ApiKey
        {
            get { return _ApiKey; }
            set => _ApiKey = GetTokenAfterApiKeySet(value).GetAwaiter().GetResult();
        }

        private static string _Token;

        public static string Token
        {
            get { return _Token; }
            set { _Token = value; }
        }

        private static DateTime _TokenExpiresIn;
        public static DateTime TokenExpiresIn
        {
            get { return _TokenExpiresIn; }
            set { _TokenExpiresIn = value; }
        }

        private static string _Url;

        public static string Url
        {
            get { return _Url; }
            set { _Url = value; }
        }

        private static Timer Timer { get; set; }
        private static int TimerInternval { get; set; }

        static CASConfiguration()
        {
            Url = "https://localhost:7189";
            TimerInternval = 15;
        }

        public static async Task<string> GetTokenAfterApiKeySet(string apiKey)
        {
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = Url + Constants.ApiRoutes.Token;
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.ApiKey, apiKey);
            HttpResponseMessage response = await httpClient.GetAsync(url);
            while (!response.IsSuccessStatusCode)
            {
                response = await httpClient.GetAsync(url);
            }
            JsonSerializerOptions options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            GetTokenResponse tokenResponse = JsonSerializer.Deserialize<GetTokenResponse>(await response.Content.ReadAsStringAsync(), options);
            Token = tokenResponse.Token;
            // Set timer for auto token refresh
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jsonToken = tokenHandler.ReadToken(Token) as JwtSecurityToken;
            TokenExpiresIn = jsonToken.ValidTo;
            Timer = new Timer(GetRefreshToken, null, TimeSpan.FromSeconds(TimerInternval), TimeSpan.FromSeconds(TimerInternval));
            return apiKey;
        }

        public static async void GetRefreshToken(object state)
        {
            if (DateTime.UtcNow.AddMinutes(5) >= TokenExpiresIn)
            {
                HttpClientSingleton httpClient = HttpClientSingleton.Instance;
                string url = Url + Constants.ApiRoutes.Token + Constants.ApiRoutes.RefreshToken;
                httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, Token);
                HttpResponseMessage response = await httpClient.GetAsync(url);
                while (!response.IsSuccessStatusCode)
                {
                    response = await httpClient.GetAsync(url);
                }
                JsonSerializerOptions options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                GetTokenResponse tokenResponse = JsonSerializer.Deserialize<GetTokenResponse>(await response.Content.ReadAsStringAsync(), options);
                Token = tokenResponse.Token;
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jsonToken = tokenHandler.ReadToken(Token) as JwtSecurityToken;
                TokenExpiresIn = jsonToken.ValidTo;
            }
        }
    }
}
