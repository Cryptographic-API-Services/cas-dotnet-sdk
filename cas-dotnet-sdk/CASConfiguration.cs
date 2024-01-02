using CasDotnetSdk.Queues;
using CasDotnetSdk.Storage;

namespace CasDotnetSdk
{
    public static class CASConfiguration
    {
        private static string _ApiKey;

        public static string ApiKey
        {
            get { return _ApiKey; }
            set => _ApiKey = TokenCache.GetTokenAfterApiKeySet(value).GetAwaiter().GetResult();
        }

        private static string _Url;

        internal static string Url
        {
            get { return _Url; }
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
        static CASConfiguration()
        {
            Url = "https://localhost:7189";
            TokenCache = new TokenCache();
            BenchmarkSenderQueue = new BenchmarkSenderRetryQueue();
        }
    }
}
