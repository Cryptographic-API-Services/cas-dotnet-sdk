using BenchmarkDotNet.Attributes;
using CasDotnetSdk.Compression;

namespace CasDotnetSdkBenchmarks.Benchmarks
{
    [BenchmarkCategory(Categories.Compression)]
    public class ZstdBenchmarks
    {
        private readonly ZSTDWrapper _zstd = new ZSTDWrapper();
        private readonly byte[] _data = Payloads.Compressible(Payloads.OneMiB);
        private byte[] _compressed = Array.Empty<byte>();

        [Params(1, 3, 19)]
        public int Level { get; set; }

        [GlobalSetup]
        public void Setup() => _compressed = _zstd.Compress(_data, Level);

        [Benchmark]
        public byte[] Compress() => _zstd.Compress(_data, Level);

        [Benchmark]
        public byte[] Decompress() => _zstd.Decompress(_compressed);
    }
}
