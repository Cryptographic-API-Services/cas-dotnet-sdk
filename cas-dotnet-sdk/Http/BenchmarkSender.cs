using CasDotnetSdk.Symmetric;
using CasDotnetSdk.Types;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
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
            else if (string.IsNullOrEmpty(CASConfiguration.TokenCache.Token))
            {
                result = false;
            }
            else if (string.IsNullOrEmpty(CASConfiguration.DiffieHellmanExchange.AESKey))
            {
                result = false;
            }
            else if (string.IsNullOrEmpty(CASConfiguration.DiffieHellmanExchange.AesNonce))
            {
                result = false;
            }
            else if (DateTime.UtcNow >= CASConfiguration.TokenCache.TokenExpiresIn)
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
                BenchmarkSDKMethod newBenchmarkSub = new BenchmarkSDKMethod()
                {
                    MethodDescription = methodDescription,
                    MethodStart = start,
                    MethodEnd = end,
                    MethodName = methodName,
                    MethodType = type,
                };
                byte[] newBenchMarkBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(newBenchmarkSub));
                AESWrapper aesWrapper = new AESWrapper();
                byte[] encryptedBenchmark = aesWrapper.Aes256EncryptBytes(CASConfiguration.DiffieHellmanExchange.AesNonce, CASConfiguration.DiffieHellmanExchange.AESKey, newBenchMarkBytes, false);
                BenchmarkMacAddressSDKMethod newBenchmark = new BenchmarkMacAddressSDKMethod()
                {
                    MacAddress = CASConfiguration.Networking.MacAddress,
                    EncryptedBenchMarkSend = encryptedBenchmark
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

        public async Task<bool> SendNewBenchmarkMethodRetry(BenchmarkMacAddressSDKMethod retryBenchmark)
        {
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + Constants.ApiRoutes.BenchmarkSDKMethodController + Constants.ApiRoutes.MethodBenchmark;
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage response = await httpClient.PostAsJsonAsync(url, retryBenchmark);
            return response.IsSuccessStatusCode;
        }
    }
}
