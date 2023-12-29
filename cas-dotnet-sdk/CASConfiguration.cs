using CASHelpers;
using System.Net.Http;
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

        private static string _Url;

        public static string Url
        {
            get { return _Url; }
            set { _Url = value; }
        }

        static CASConfiguration()
        {
            Url = "https://localhost:7189";
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


            return apiKey;
        }
    }
}
