using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers.Windows
{
    internal static class FreeMemoryHelperWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
