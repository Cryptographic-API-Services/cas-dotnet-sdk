using System;
using System.Runtime.InteropServices;

namespace EasDotnetSdk.Helpers
{
    /// <summary>
    /// Simple class that contains a method to get the current operating system platform.
    /// In most cases this library will only be running on a Windows or Linux Server.
    /// We don't really need FreeBSD or OSX support.
    /// </summary>
    public class OperatingSystemDeterminator
    {
        public OSPlatform GetOperatingSystem()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return OSPlatform.Windows;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return OSPlatform.Linux;
            }
            throw new Exception("Cannot determine unsupported operating system.");
        }
    }
}
