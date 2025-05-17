using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using CASHelpers;

namespace CasDotnetSdk.Queues
{
    internal class IsThreadingProductEnabled
    {
        private Timer Timer { get; set; }
        private int Interval { get; set; }

        public IsThreadingProductEnabled()
        {
            this.Interval = 1;
            this.Timer = new Timer(ValidateThreadingProductSubscriptionCallback, null, TimeSpan.FromHours(this.Interval), TimeSpan.FromHours(this.Interval));
        }
        private async void ValidateThreadingProductSubscriptionCallback(object state)
        {
            await SendRequestToApi();
        }

        public async Task ValidateThreadingProductSubscription()
        {
            await SendRequestToApi();
        }

        private async Task SendRequestToApi()
        {
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + "/Payments/ValidateProductSignature";
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage response = await httpClient.GetAsync(url);
            CASConfiguration.IsThreadingEnabled = response.IsSuccessStatusCode;
        }
    }
}
