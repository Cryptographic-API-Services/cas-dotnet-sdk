using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class SHAWindowsWrapper
    {

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr sha512(string password);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr sha256(string password);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
