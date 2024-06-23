using CasDotnetSdk.Http;
using CASHelpers;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Models
{
    public class BaseWrapper
    {
        internal readonly OSPlatform _platform;
        internal readonly BenchmarkSender _sender;

        public BaseWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._sender = new BenchmarkSender();
        }
    }
}
