using BenchmarkDotNet.Attributes;
using CasDotnetSdk.PasswordHashers;

namespace CasDotnetSdkBenchmarks.Benchmarks
{
    /// <summary>
    /// Password hashers are slow on purpose. These measure the SDK's default cost
    /// settings (HashPassword), which is what most callers get; tune with
    /// HashPasswordWithParameters and compare against these numbers.
    /// </summary>
    [BenchmarkCategory(Categories.PasswordHashing)]
    public class PasswordHasherBenchmarks
    {
        private readonly Argon2Wrapper _argon2 = new Argon2Wrapper();
        private readonly BcryptWrapper _bcrypt = new BcryptWrapper();
        private readonly SCryptWrapper _scrypt = new SCryptWrapper();
        private string _argon2Hash = string.Empty;
        private string _bcryptHash = string.Empty;
        private string _scryptHash = string.Empty;
        private byte[] _salt = Array.Empty<byte>();

        [GlobalSetup]
        public void Setup()
        {
            _argon2Hash = _argon2.HashPassword(Payloads.Password);
            _bcryptHash = _bcrypt.HashPassword(Payloads.Password);
            _scryptHash = _scrypt.HashPassword(Payloads.Password);
            _salt = _argon2.GenerateSalt();
        }

        [Benchmark]
        public string Argon2Hash() => _argon2.HashPassword(Payloads.Password);

        [Benchmark]
        public bool Argon2Verify() => _argon2.Verify(_argon2Hash, Payloads.Password);

        [Benchmark]
        public byte[] Argon2DeriveAes256Key() => _argon2.DeriveAES256Key(Payloads.Password, _salt);

        [Benchmark]
        public string BcryptHash() => _bcrypt.HashPassword(Payloads.Password);

        [Benchmark]
        public bool BcryptVerify() => _bcrypt.Verify(_bcryptHash, Payloads.Password);

        [Benchmark]
        public string SCryptHash() => _scrypt.HashPassword(Payloads.Password);

        [Benchmark]
        public bool SCryptVerify() => _scrypt.Verify(_scryptHash, Payloads.Password);
    }
}
