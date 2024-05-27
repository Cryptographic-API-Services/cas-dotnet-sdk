using CasDotnetSdk.Helpers.Linux;
using CasDotnetSdk.Helpers.Windows;
using CASHelpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers
{
    internal static class FreeMemoryHelper
    {
        private static readonly OSPlatform _operatingSystem;
        static FreeMemoryHelper()
        {
            _operatingSystem = new OperatingSystemDeterminator().GetOperatingSystem();
        }
        public static void FreeCStringMemory(IntPtr memoryToFree)
        {
            if (_operatingSystem == OSPlatform.Linux)
            {
                FreeMemoryHelperLinuxWrapper.free_cstring(memoryToFree);
            }
            else
            {
                FreeMemoryHelperWindowsWrapper.free_cstring(memoryToFree);
            }
        }   

        public static void FreeBytesMemory(IntPtr memoryToFree)
        {
            if (_operatingSystem == OSPlatform.Linux)
            {
                FreeMemoryHelperLinuxWrapper.free_bytes(memoryToFree);
            }
            else
            {
                FreeMemoryHelperWindowsWrapper.free_bytes(memoryToFree);
            }
        }
    }
}
