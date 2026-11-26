using BenchmarkDotNet.Attributes;
using CasDotnetSdk.Hashers;

namespace CasDotnetSdkBenchmarks.Benchmarks
{
    [BenchmarkCategory(Categories.Hashing)]
    public class HasherBenchmarks
    {
        private readonly SHAWrapper _sha3 = new SHAWrapper();
        private readonly SHA2Wrapper _sha2 = new SHA2Wrapper();
        private readonly Blake2Wrapper _blake2 = new Blake2Wrapper();
        private byte[] _data = Array.Empty<byte>();

        [Params(Payloads.OneKiB, Payloads.OneMiB)]
        public int Size { get; set; }

        [GlobalSetup]
        public void Setup() => _data = Payloads.RandomBytes(Size);

        [Benchmark]
        public byte[] Sha3_256() => _sha3.Hash256(_data);

        [Benchmark]
        public byte[] Sha3_512() => _sha3.Hash512(_data);

        [Benchmark]
        public byte[] Sha256() => _sha2.Hash256(_data);

        [Benchmark]
        public byte[] Sha512() => _sha2.Hash512(_data);

        [Benchmark]
        public byte[] Blake2s_256() => _blake2.Hash256(_data);

        [Benchmark]
        public byte[] Blake2b_512() => _blake2.Hash512(_data);
    }

    [BenchmarkCategory(Categories.Hashing)]
    public class HmacBenchmarks
    {
        private readonly HmacWrapper _hmac = new HmacWrapper();
        private readonly byte[] _key = Payloads.RandomBytes(32, seed: 7);
        private byte[] _data = Array.Empty<byte>();
        private byte[] _tag = Array.Empty<byte>();

        [Params(Payloads.OneKiB, Payloads.OneMiB)]
        public int Size { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            _data = Payloads.RandomBytes(Size);
            _tag = _hmac.HmacSignBytes(_key, _data);
        }

        [Benchmark]
        public byte[] HmacSha256Sign() => _hmac.HmacSignBytes(_key, _data);

        [Benchmark]
        public bool HmacSha256Verify() => _hmac.HmacVerifyBytes(_key, _data, _tag);
    }
}
