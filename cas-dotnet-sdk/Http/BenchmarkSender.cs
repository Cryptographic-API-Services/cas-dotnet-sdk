using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

namespace CasDotnetSdk.Http
{
    internal class BenchmarkSender
    {
        private bool CanSend()
        {
            bool result = true;
            if (string.IsNullOrEmpty(CASConfiguration.ApiKey))
            {
                result = false;
            }
            if (string.IsNullOrEmpty(CASConfiguration.TokenCache.Token))
            {
                result = false;
            }
            if (DateTime.UtcNow >= CASConfiguration.TokenCache.TokenExpiresIn)
            {
                result = false;
            }
            return result;
        }


        public async Task SendNewBenchmarkMethod(string methodName, DateTime start, DateTime end, BenchmarkMethodType type, string? methodDescription = null)
        {
            if (this.CanSend())
            {

                HttpClientSingleton httpClient = HttpClientSingleton.Instance;
                string url = CASConfiguration.Url + Constants.ApiRoutes.BenchmarkSDKMethodController + Constants.ApiRoutes.MethodBenchmark;
                BenchmarkSDKMethod newBenchmark = new BenchmarkSDKMethod()
                {
                    MethodDescription = methodDescription,
                    MethodStart = start,
                    MethodEnd = end,
                    MethodName = methodName,
                    MethodType = type,
                };
                httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
                HttpResponseMessage response = await httpClient.PostAsJsonAsync(url, newBenchmark);
                if (!response.IsSuccessStatusCode)
                {
                    // Put into retry queue
                    CASConfiguration.BenchmarkSenderQueue.Enqueue(newBenchmark);
                }
            }
        }

        public async Task<bool> SendNewBenchmarkMethodRetry(BenchmarkSDKMethod retryBenchmark)
        {
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + Constants.ApiRoutes.BenchmarkSDKMethodController + Constants.ApiRoutes.MethodBenchmark;
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage response = await httpClient.PostAsJsonAsync(url, retryBenchmark);
            return response.IsSuccessStatusCode;
        }
    }
}
