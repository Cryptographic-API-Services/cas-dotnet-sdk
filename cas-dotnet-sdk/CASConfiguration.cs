using CasDotnetSdk.Configuration;
using CasDotnetSdk.Models;
using CasDotnetSdk.Queues;
using CasDotnetSdk.Storage;
using CASHelpers;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace CasDotnetSdk
{
    public static class CASConfiguration
    {
        static CASConfiguration()
        {
            IsDevelopment = false;
            Url = "https://encryptionapiservices.com";
            TokenCache = new TokenCache();
            BenchmarkSenderQueue = new BenchmarkSenderRetryQueue();
            Networking = new Networking();
            DiffieHellmanExchange = new DiffieHellmanExchange();
        }

        private static string _ApiKey;
        public static string ApiKey
        {
            get { return _ApiKey; }
            set
            {
                AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
                _ApiKey = TokenCache.GetTokenAfterApiKeySet(value).GetAwaiter().GetResult();
                SendOSInformation(value).GetAwaiter().GetResult();
                DiffieHellmanExchange.CreateSharedSecretWithServer().GetAwaiter().GetResult();
            }
        }

        private static bool _IsDevelopment;
        public static bool IsDevelopment
        {
            get { return _IsDevelopment; }
            set { _IsDevelopment = value; }
        }

        private static string _Url;
        internal static string Url
        {
            get
            {
                if (_IsDevelopment)
                {
                    return "https://localhost7189";
                }
                else
                {
                    return _Url;
                }
            }
            set { _Url = value; }
        }

        private static TokenCache _TokenCache;
        internal static TokenCache TokenCache
        {
            get { return _TokenCache; }
            set { _TokenCache = value; }
        }

        private static BenchmarkSenderRetryQueue _BenchmarkSenderQueue;
        internal static BenchmarkSenderRetryQueue BenchmarkSenderQueue
        {
            get { return _BenchmarkSenderQueue; }
            set { _BenchmarkSenderQueue = value; }
        }

        private static Networking _Networking;
        internal static Networking Networking
        {
            get { return _Networking; }
            set { _Networking = value; }
        }

        private static DiffieHellmanExchange _DiffieHellmanExchange;
        internal static DiffieHellmanExchange DiffieHellmanExchange
        {
            get { return _DiffieHellmanExchange; }
            set { _DiffieHellmanExchange = value; }
        }

        private static async Task SendOSInformation(string apiKey)
        {
            OperatingSystemDeterminator osd = new OperatingSystemDeterminator();
            OSInfoCacheSend osInfoSend = new OSInfoCacheSend()
            {
                OperatingSystem = osd.OperationSystemVersionString()
            };
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + "/Authentication/OperatingSystemCacheStore";
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, TokenCache.Token);
            HttpResponseMessage response = await httpClient.PostAsJsonAsync(url, osInfoSend);
            if (!response.IsSuccessStatusCode)
            {
                string errorMessage = await response.Content.ReadAsStringAsync();
                // will stop the process by throwing an exception
                throw new Exception(errorMessage);
            }
        }

        private static void OnProcessExit(object sender, EventArgs e)
        {
            OnProcessExit onProcExit = new OnProcessExit();
            onProcExit.StartProcessCustomExit().GetAwaiter().GetResult();
        }
    }
}
