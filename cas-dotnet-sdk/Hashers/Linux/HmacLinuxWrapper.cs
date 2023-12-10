using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class HmacLinuxWrapper
    {

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr hmac_sign(string key, string message);
        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify(string key, string message, string signature);
        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
