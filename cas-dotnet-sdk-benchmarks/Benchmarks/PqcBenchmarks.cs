using BenchmarkDotNet.Attributes;
using CasDotnetSdk.PQC;
using CasDotnetSdk.PQC.Types;

namespace CasDotnetSdkBenchmarks.Benchmarks
{
    [BenchmarkCategory(Categories.PostQuantum)]
    public class MLKEMBenchmarks
    {
        private readonly MLKEMWrapper _mlKem = new MLKEMWrapper();
        private MLKemKeyPair _keyPair = new MLKemKeyPair();
        private MLKemEncapsulateResult _encapsulated = new MLKemEncapsulateResult();

        [GlobalSetup]
        public void Setup()
        {
            _keyPair = _mlKem.GenerateKeyPair();
            _encapsulated = _mlKem.Encapsulate(_keyPair.PublicKey);
        }

        [Benchmark]
        [BenchmarkCategory(Categories.KeyGeneration)]
        public MLKemKeyPair GenerateKeyPair() => _mlKem.GenerateKeyPair();

        [Benchmark]
        public MLKemEncapsulateResult Encapsulate() => _mlKem.Encapsulate(_keyPair.PublicKey);

        [Benchmark]
        public byte[] Decapsulate() => _mlKem.Decapsulate(_keyPair.SecretKey, _encapsulated.Ciphertext);
    }

    [BenchmarkCategory(Categories.PostQuantum)]
    public class MLDSABenchmarks
    {
        private readonly MLDSAWrapper _mlDsa = new MLDSAWrapper();
        private readonly byte[] _message = Payloads.RandomBytes(Payloads.OneKiB);
        private MLDSAKeyPair _keyPair = new MLDSAKeyPair();
        private byte[] _signature = Array.Empty<byte>();

        [GlobalSetup]
        public void Setup()
        {
            _keyPair = _mlDsa.GenerateSigningAndVerificationKey();
            _signature = _mlDsa.Sign(_keyPair.SigningKey, _message);
        }

        [Benchmark]
        [BenchmarkCategory(Categories.KeyGeneration)]
        public MLDSAKeyPair GenerateKeyPair() => _mlDsa.GenerateSigningAndVerificationKey();

        [Benchmark]
        public byte[] Sign() => _mlDsa.Sign(_keyPair.SigningKey, _message);

        [Benchmark]
        public bool Verify() => _mlDsa.Verify(_keyPair.VerificationKey, _signature, _message);
    }

    [BenchmarkCategory(Categories.PostQuantum)]
    public class SLHDSABenchmarks
    {
        private readonly SLHDSAWrapper _slhDsa = new SLHDSAWrapper();
        private readonly byte[] _message = Payloads.RandomBytes(Payloads.OneKiB);
        private SLHDSAKeyPair _keyPair = new SLHDSAKeyPair();
        private byte[] _signature = Array.Empty<byte>();

        [GlobalSetup]
        public void Setup()
        {
            _keyPair = _slhDsa.GenerateSigningAndVerificationKey();
            _signature = _slhDsa.Sign(_keyPair.SigningKey, _message);
        }

        [Benchmark]
        [BenchmarkCategory(Categories.KeyGeneration)]
        public SLHDSAKeyPair GenerateKeyPair() => _slhDsa.GenerateSigningAndVerificationKey();

        [Benchmark]
        public byte[] Sign() => _slhDsa.Sign(_keyPair.SigningKey, _message);

        [Benchmark]
        public bool Verify() => _slhDsa.Verify(_keyPair.VerificationKey, _signature, _message);
    }
}
