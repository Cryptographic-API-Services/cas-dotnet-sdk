using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers;
using System.Runtime.InteropServices;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Argon2WrapperTests
    {
        private Argon2Wrappper _argon2Wrapper;
        private readonly OperatingSystemDeterminator _operatingSystem;

        public Argon2WrapperTests()
        {
            this._argon2Wrapper = new Argon2Wrappper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void HashPassword()
        {
            string password = "DoNotUSETHISPASS@!";
            string hash = this._argon2Wrapper.HashPassword(password);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Verify()
        {
            string password = "TestPasswordToVerify";
            string hash = this._argon2Wrapper.HashPassword(password);
            bool isValid = this._argon2Wrapper.VerifyPassword(hash, password);
            Assert.True(isValid);
        }
    }
}
