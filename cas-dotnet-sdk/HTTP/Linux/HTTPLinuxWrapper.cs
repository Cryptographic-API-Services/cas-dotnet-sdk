using System.Runtime.InteropServices;

namespace CasDotnetSdk.HTTP.Linux
{
    internal static class HTTPLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern void set_base_url(string baseUrl);

        [DllImport("libcas_core_lib.so")]
        public static extern void set_api_key(string apiKey);

        [DllImport("libcas_core_lib.so")]
        public static extern void send_benchmark_to_api(long timeInMilliseconds, string className, string methodName);
    }
}
