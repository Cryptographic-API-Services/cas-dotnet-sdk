using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class HmacWindowsWrapper
    {

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr hmac_sign(string key, string message);
        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify(string key, string message, string signature);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
