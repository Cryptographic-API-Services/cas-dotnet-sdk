using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers.Linux
{
    internal static class FreeMemoryHelperLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
