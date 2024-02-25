using CasDotnetSdk.Storage;
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
            // Remove operating system cache on server
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + "/Authentication/OperatingSystemCacheRemove";
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage respoonse = await httpClient.PutAsync(url, null);
        }
    }
}
