using BenchmarkDotNet.Attributes;
using CasDotnetSdk.Sponges;
using CasDotnetSdk.Symmetric;

namespace CasDotnetSdkBenchmarks.Benchmarks
{
    /// <summary>
    /// AEAD ciphers through the Seal/Open API, which draws a fresh nonce for every
    /// message (as callers should), so each Seal includes nonce generation.
    /// </summary>
    [BenchmarkCategory(Categories.Symmetric)]
    public class SymmetricBenchmarks
    {
        private readonly AESWrapper _aes = new AESWrapper();
        private readonly AesGcmSivWrapper _aesGcmSiv = new AesGcmSivWrapper();
        private readonly ChaCha20Poly1305Wrapper _chacha = new ChaCha20Poly1305Wrapper();
        private readonly AsconWrapper _ascon = new AsconWrapper();

        private byte[] _plaintext = Array.Empty<byte>();
        private byte[] _aes128Key = Array.Empty<byte>();
        private byte[] _aes256Key = Array.Empty<byte>();
        private byte[] _aes256GcmSivKey = Array.Empty<byte>();
        private byte[] _chachaKey = Array.Empty<byte>();
        private byte[] _asconKey = Array.Empty<byte>();

        private byte[] _aes128Sealed = Array.Empty<byte>();
        private byte[] _aes256Sealed = Array.Empty<byte>();
        private byte[] _aes256GcmSivSealed = Array.Empty<byte>();
        private byte[] _chachaSealed = Array.Empty<byte>();
        private byte[] _asconSealed = Array.Empty<byte>();

        [Params(Payloads.OneKiB, Payloads.OneMiB)]
        public int Size { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            _plaintext = Payloads.RandomBytes(Size);

            _aes128Key = _aes.Aes128Key();
            _aes256Key = _aes.Aes256Key();
            _aes256GcmSivKey = _aesGcmSiv.Aes256GcmSivKey();
            _chachaKey = _chacha.ChaCha20Poly1305Key();
            _asconKey = _ascon.Ascon128Key();

            _aes128Sealed = _aes.Aes128Seal(_aes128Key, _plaintext);
            _aes256Sealed = _aes.Aes256Seal(_aes256Key, _plaintext);
            _aes256GcmSivSealed = _aesGcmSiv.Aes256GcmSivSeal(_aes256GcmSivKey, _plaintext);
            _chachaSealed = _chacha.ChaCha20Poly1305Seal(_chachaKey, _plaintext);
            _asconSealed = _ascon.Ascon128Seal(_asconKey, _plaintext);
        }

        [Benchmark]
        public byte[] Aes128GcmSeal() => _aes.Aes128Seal(_aes128Key, _plaintext);

        [Benchmark]
        public byte[] Aes128GcmOpen() => _aes.Aes128Open(_aes128Key, _aes128Sealed);

        [Benchmark]
        public byte[] Aes256GcmSeal() => _aes.Aes256Seal(_aes256Key, _plaintext);

        [Benchmark]
        public byte[] Aes256GcmOpen() => _aes.Aes256Open(_aes256Key, _aes256Sealed);

        [Benchmark]
        public byte[] Aes256GcmSivSeal() => _aesGcmSiv.Aes256GcmSivSeal(_aes256GcmSivKey, _plaintext);

        [Benchmark]
        public byte[] Aes256GcmSivOpen() => _aesGcmSiv.Aes256GcmSivOpen(_aes256GcmSivKey, _aes256GcmSivSealed);

        [Benchmark]
        public byte[] ChaCha20Poly1305Seal() => _chacha.ChaCha20Poly1305Seal(_chachaKey, _plaintext);

        [Benchmark]
        public byte[] ChaCha20Poly1305Open() => _chacha.ChaCha20Poly1305Open(_chachaKey, _chachaSealed);

        [Benchmark]
        public byte[] Ascon128Seal() => _ascon.Ascon128Seal(_asconKey, _plaintext);

        [Benchmark]
        public byte[] Ascon128Open() => _ascon.Ascon128Open(_asconKey, _asconSealed);
    }
}
