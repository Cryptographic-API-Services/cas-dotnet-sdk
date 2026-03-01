using System.Runtime.InteropServices;

namespace CasDotnetSdk.HTTP.Windows
{
    internal static class HTTPWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern void set_base_url(string baseUrl);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool set_api_key(string apiKey);

        [DllImport("cas_core_lib.dll")]
        public static extern void send_benchmark_to_api(long timeInMilliseconds, string className, string methodName);
    }
}