using BenchmarkDotNet.Attributes;
using CasDotnetSdk.PasswordHashers;

namespace CasDotnetSdkBenchmarks
{
    public class Argon2Benchmark
    {
        private readonly Argon2Wrapper _argon2Wrapper;
        private readonly string _passwordToHash;
        public Argon2Benchmark()
        {
            this._argon2Wrapper = new Argon2Wrapper();
            this._passwordToHash = "asdasdasd23454674567fdgh34tdcfb2345";
        }

        [Benchmark]
        public string HashPassword()
        {
            return this._argon2Wrapper.HashPassword(this._passwordToHash);
        }

        [Benchmark]
        public bool Verify()
        {
            string hash = this._argon2Wrapper.HashPassword(this._passwordToHash);
            return this._argon2Wrapper.Verify(hash, this._passwordToHash);
        }
    }
}
