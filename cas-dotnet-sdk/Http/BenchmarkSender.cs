using CasDotnetSdk.Symmetric;
using CasDotnetSdk.Types;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace CasDotnetSdk.Http
{
    public class BenchmarkSender
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
            else if (CASConfiguration.DiffieHellmanExchange?.AESKey == null || CASConfiguration.DiffieHellmanExchange?.AESKey?.Length == 0)
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
                byte[] aesNonce = aesWrapper.GenerateAESNonce(false);
                byte[] encryptedBenchmark = aesWrapper.Aes256Encrypt(aesNonce, CASConfiguration.DiffieHellmanExchange.AESKey, newBenchMarkBytes, false);
                BenchmarkMacAddressSDKMethod newBenchmark = new BenchmarkMacAddressSDKMethod()
                {
                    MacAddress = CASConfiguration.Networking.MacAddress,
                    EncryptedBenchMarkSend = encryptedBenchmark,
                    AesNonce = aesNonce
                };
                httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
                HttpResponseMessage response = await httpClient.PostAsJsonAsync(url, newBenchmark);
                if (!response.IsSuccessStatusCode && response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    CASConfiguration.ApiKey = null;
                    CASConfiguration.TokenCache.Token = null;
                }
                else if (!response.IsSuccessStatusCode)
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
