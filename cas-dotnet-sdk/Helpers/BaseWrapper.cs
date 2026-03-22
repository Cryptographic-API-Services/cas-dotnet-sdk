
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// The main class that external facing wrapper classes inherit from that contains the benchmark sender and platform getter.
    /// </summary>
    public class BaseWrapper
    {
        public readonly OSPlatform _platform;
        public BaseWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }
    }

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

        public string OperationSystemVersionString()
        {
            OperatingSystem os = Environment.OSVersion;
            return os.VersionString;
        }
    }
}
