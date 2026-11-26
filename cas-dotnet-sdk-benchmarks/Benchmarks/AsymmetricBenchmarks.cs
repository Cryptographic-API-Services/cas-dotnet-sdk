using BenchmarkDotNet.Attributes;
using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Hybrid.Types;
using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;

namespace CasDotnetSdkBenchmarks.Benchmarks
{
    [BenchmarkCategory(Categories.Asymmetric)]
    public class RsaBenchmarks
    {
        private readonly RSAWrapper _rsa = new RSAWrapper();
        private readonly byte[] _message = Payloads.RandomBytes(Payloads.OneKiB);
        private RsaKeyPairResult _keyPair = new RsaKeyPairResult();
        private byte[] _signature = Array.Empty<byte>();
        private byte[] _pssSignature = Array.Empty<byte>();

        [Params(2048, 4096)]
        public int KeySize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            _keyPair = _rsa.GetKeyPair(KeySize);
            _signature = _rsa.Sign(_keyPair.PrivateKey, _message);
            _pssSignature = _rsa.SignPss(_keyPair.PrivateKey, _message);
        }

        [Benchmark]
        public byte[] Pkcs1Sign() => _rsa.Sign(_keyPair.PrivateKey, _message);

        [Benchmark]
        public bool Pkcs1Verify() => _rsa.Verify(_keyPair.PublicKey, _message, _signature);

        [Benchmark]
        public byte[] PssSign() => _rsa.SignPss(_keyPair.PrivateKey, _message);

        [Benchmark]
        public bool PssVerify() => _rsa.VerifyPss(_keyPair.PublicKey, _message, _pssSignature);
    }

    /// <summary>
    /// RSA key generation searches for random primes, so its time varies widely from
    /// one call to the next; expect a large error column. 4096-bit takes seconds per key.
    /// </summary>
    [BenchmarkCategory(Categories.Asymmetric, Categories.KeyGeneration)]
    public class RsaKeyGenerationBenchmarks
    {
        private readonly RSAWrapper _rsa = new RSAWrapper();

        [Benchmark]
        public RsaKeyPairResult GenerateKeyPair2048() => _rsa.GetKeyPair(2048);
    }

    [BenchmarkCategory(Categories.Asymmetric)]
    public class Ed25519Benchmarks
    {
        private readonly ED25519Wrapper _ed25519 = new ED25519Wrapper();
        private readonly byte[] _message = Payloads.RandomBytes(Payloads.OneKiB);
        private Ed25519KeyPairResult _keyPair = new Ed25519KeyPairResult();
        private byte[] _signature = Array.Empty<byte>();

        [GlobalSetup]
        public void Setup()
        {
            _keyPair = _ed25519.GetKeyPair();
            _signature = _ed25519.SignBytes(_keyPair.SigningKey, _message).Signature;
        }

        [Benchmark]
        [BenchmarkCategory(Categories.KeyGeneration)]
        public Ed25519KeyPairResult GenerateKeyPair() => _ed25519.GetKeyPair();

        [Benchmark]
        public Ed25519ByteSignatureResult Sign() => _ed25519.SignBytes(_keyPair.SigningKey, _message);

        [Benchmark]
        public bool Verify() => _ed25519.VerifyWithPublicKeyBytes(_keyPair.VerifyingKey, _signature, _message);
    }

    [BenchmarkCategory(Categories.Asymmetric)]
    public class X25519Benchmarks
    {
        private readonly X25519Wrapper _x25519 = new X25519Wrapper();
        private X25519SecretPublicKey _alice = new X25519SecretPublicKey();
        private X25519SecretPublicKey _bob = new X25519SecretPublicKey();

        [GlobalSetup]
        public void Setup()
        {
            _alice = _x25519.GenerateSecretAndPublicKey();
            _bob = _x25519.GenerateSecretAndPublicKey();
        }

        [Benchmark]
        [BenchmarkCategory(Categories.KeyGeneration)]
        public X25519SecretPublicKey GenerateKeyPair() => _x25519.GenerateSecretAndPublicKey();

        [Benchmark]
        public X25519SharedSecret SharedSecret() => _x25519.GenerateSharedSecret(_alice.SecretKey, _bob.PublicKey);
    }

    [BenchmarkCategory(Categories.Asymmetric)]
    public class HpkeBenchmarks
    {
        private readonly HpkeWrapper _hpke = new HpkeWrapper();
        private readonly byte[] _plaintext = Payloads.RandomBytes(Payloads.OneKiB);
        private HpkeKeyPairResult _keyPair = new HpkeKeyPairResult();
        private HpkeEncryptResult _encrypted = new HpkeEncryptResult();

        [GlobalSetup]
        public void Setup()
        {
            _keyPair = _hpke.GenerateKeyPair();
            _encrypted = _hpke.Encrypt(_plaintext, _keyPair.PublicKey, _keyPair.InfoStr);
        }

        [Benchmark]
        [BenchmarkCategory(Categories.KeyGeneration)]
        public HpkeKeyPairResult GenerateKeyPair() => _hpke.GenerateKeyPair();

        [Benchmark]
        public HpkeEncryptResult Encrypt() => _hpke.Encrypt(_plaintext, _keyPair.PublicKey, _keyPair.InfoStr);

        [Benchmark]
        public byte[] Decrypt() => _hpke.Decrypt(_encrypted.Ciphertext, _keyPair.PrivateKey, _encrypted.EncappedKey, _encrypted.Tag, _keyPair.InfoStr);
    }
}
