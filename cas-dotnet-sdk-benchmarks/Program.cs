using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;

namespace CasDotnetSdkBenchmarks
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            // BenchmarkDotNet builds each run in a separate, generated project that
            // references this one, using `dotnet build` in a child process. The native
            // library was built and staged when this program was built, so skip the Rust
            // build (and its cargo requirement) there. MSBuild reads environment
            // variables as properties, and the child process inherits this one. (A
            // job-level MSBuild argument would also work, but it would replace the job
            // chosen with --job.)
            Environment.SetEnvironmentVariable("BuildNativeRust", "false");

            IConfig config = DefaultConfig.Instance
                .AddDiagnoser(MemoryDiagnoser.Default);

            var summaries = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);

            // BenchmarkDotNet exits with 0 even when a benchmark throws or fails to build,
            // which would let CI pass on a broken benchmark.
            bool failed = summaries.Any(s => s.HasCriticalValidationErrors || s.Reports.Any(r => !r.Success));
            return failed ? 1 : 0;
        }
    }
}
