using CasDotnetSdk.Http;
using CASHelpers;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Helpers
{
    /// <summary>
    /// The main class that external facing wrapper classes inherit from that contains the benchmark sender and platform getter.
    /// </summary>
    public class BaseWrapper
    {
        public readonly OSPlatform _platform;
        public readonly BenchmarkSender _sender;
        public BaseWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._sender = new BenchmarkSender();
        }
    }
}
