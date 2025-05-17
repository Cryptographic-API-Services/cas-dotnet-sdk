using System.Runtime.InteropServices;
using CASHelpers;

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
}
