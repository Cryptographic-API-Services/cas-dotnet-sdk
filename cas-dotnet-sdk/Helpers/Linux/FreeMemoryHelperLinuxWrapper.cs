using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers.Linux
{
    internal static class FreeMemoryHelperLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
