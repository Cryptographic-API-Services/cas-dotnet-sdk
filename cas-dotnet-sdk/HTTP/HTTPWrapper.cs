using CasDotnetSdk.HTTP.Linux;
using CasDotnetSdk.HTTP.Windows;
using CASHelpers;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.HTTP
{
    public static class HTTPWrapper
    {
        private static readonly OSPlatform _operatingSystem;
        static HTTPWrapper()
        {
            _operatingSystem = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public static void SetBaseUrl(string baseUrl)
        {
            if (_operatingSystem == OSPlatform.Linux)
            {
                HTTPLinuxWrapper.set_base_url(baseUrl);
            }
            else
            {
                HTTPWindowsWrapper.set_base_url(baseUrl);
            }
        }

        public static void SetApiKey(string apiKey)
        {
            if (_operatingSystem == OSPlatform.Linux)
            {
                HTTPLinuxWrapper.set_api_key(apiKey);
            }
            else
            {
                HTTPWindowsWrapper.set_api_key(apiKey);
            }
        }

        public static void SendBenchmarkToApi(long timeInMilliseconds, string className, string methodName)
        {
            if (_operatingSystem == OSPlatform.Linux)
            {
                HTTPLinuxWrapper.send_benchmark_to_api(timeInMilliseconds, className, methodName);
            }
            else
            {
                HTTPWindowsWrapper.send_benchmark_to_api(timeInMilliseconds, className, methodName);
            }
        }
    }
}
