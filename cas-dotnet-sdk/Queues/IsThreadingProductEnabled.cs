using CASHelpers;
using System;
using System.Net.Http;
using System.Threading;

namespace CasDotnetSdk.Queues
{
    internal class IsThreadingProductEnabled
    {
        private Timer Timer { get; set; }
        private int Interval { get; set; }

        public IsThreadingProductEnabled()
        {
            this.ValidateThreadingProductSubscription(null);
            this.Interval = 1;
            this.Timer = new Timer(ValidateThreadingProductSubscription, null, TimeSpan.FromHours(this.Interval), TimeSpan.FromHours(this.Interval));
        }

        private async void ValidateThreadingProductSubscription(object state)
        {
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + "/Payments/ValidateProductSignature";
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage response = await httpClient.GetAsync(url);
            CASConfiguration.IsThreadingEnabled = response.IsSuccessStatusCode;
        }
    }
}
