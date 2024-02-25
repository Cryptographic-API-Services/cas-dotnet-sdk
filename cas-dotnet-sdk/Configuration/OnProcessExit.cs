using CASHelpers;
using System.Net.Http;
using System.Threading.Tasks;

namespace CasDotnetSdk.Configuration
{
    public class OnProcessExit
    {
        public OnProcessExit()
        {

        }
        public async Task StartProcessCustomExit()
        {
            await this.RemoveOsInformationFromServer();
            this.ClearApiTokenAndApiKey();
        }

        private async Task RemoveOsInformationFromServer()
        {
            // Remove operating system cache on server
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + "/Authentication/OperatingSystemCacheRemove";
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage respoonse = await httpClient.PutAsync(url, null);
        }

        private void ClearApiTokenAndApiKey()
        {
            CASConfiguration.TokenCache.Token = null;
            CASConfiguration.ApiKey = null;
        }
    }
}
