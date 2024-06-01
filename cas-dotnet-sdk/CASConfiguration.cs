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

        /// <summary>
        /// This is the property where you set your CAS User account API key from the CAS Dashboard.
        /// </summary>
        public static string ApiKey
        {
            get { return _ApiKey; }
            set
            {
                if (value != null)
                {
                    AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
                    _ApiKey = TokenCache.GetTokenAfterApiKeySet(value).GetAwaiter().GetResult();
                    if (_ApiKey != null)
                    {
                        Task osSendTask = SendOSInformation(value);
                        Task dhTask = DiffieHellmanExchange.CreateSharedSecretWithServer();
                        _IsThreadProductEnabled = new IsThreadingProductEnabled();
                        Task isThreadingEnabledTask = _IsThreadProductEnabled.ValidateThreadingProductSubscription();
                        Task.WhenAll(osSendTask, dhTask, isThreadingEnabledTask).GetAwaiter().GetResult();
                    }
                    else
                    {
                        throw new Exception("The API key that you supplied is not authorized");
                    }
                }
            }
        }

        private static bool _IsDevelopment;

        /// <summary>
        /// This method is mostly for development purposes of the SDk. We don't recommend changing this in a production environment.
        /// </summary>
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
                    return "https://localhost:8081";
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

        private static IsThreadingProductEnabled _IsThreadProductEnabled;
        internal static IsThreadingProductEnabled IsThreadProductEnabled
        {
            get { return _IsThreadProductEnabled; }
            set { _IsThreadProductEnabled = value; }
        }

        private static bool _IsThreadingEnabled = false;
        internal static bool IsThreadingEnabled
        {
            get { return _IsThreadingEnabled; }
            set { _IsThreadingEnabled = value; }
        }

        private static async Task SendOSInformation(string apiKey)
        {
            OperatingSystemDeterminator osd = new OperatingSystemDeterminator();
            OSInfoCacheSend osInfoSend = new OSInfoCacheSend()
            {
                OperatingSystem = osd.OperationSystemVersionString(),
                ApiKey = apiKey
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
