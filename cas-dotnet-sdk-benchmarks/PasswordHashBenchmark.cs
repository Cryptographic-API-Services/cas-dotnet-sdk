using BenchmarkDotNet.Attributes;
using CasDotnetSdk.PasswordHashers;
using Isopoh.Cryptography.Argon2;

namespace CASBenchmarks
{
    public class PasswordHashBenchmark
    {
        private readonly string _passwordToHash;
        private readonly Argon2Wrappper _argon2;
        private readonly SCryptWrapper _scryptWrapper;
        private readonly BcryptWrapper _bcryptWrapper;

        public PasswordHashBenchmark()
        {
            this._passwordToHash = "Esfo123@#!mnasdoklj()(";
            this._argon2 = new Argon2Wrappper();
            this._scryptWrapper = new SCryptWrapper();
            this._bcryptWrapper = new BcryptWrapper();
        }

        [Benchmark]
        public void CASHashArgon2()
        {
            string hashed = _argon2.HashPassword(this._passwordToHash);
        }

        [Benchmark]
        public void IsopohHashArgon2()
        {
            string hashed = Argon2.Hash(this._passwordToHash);
        }
    }
}
