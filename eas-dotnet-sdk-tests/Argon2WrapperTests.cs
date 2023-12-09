using EasDotnetSdk.Helpers;
using EasDotnetSdk.PasswordHashers;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string password = "DoNotUSETHISPASS@!";
                string hash = this._argon2Wrapper.HashPassword(password);
                Assert.NotEqual(password, hash);
            }
        }

        [Fact]
        public void Verify()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string password = "TestPasswordToVerify";
                string hash = this._argon2Wrapper.HashPassword(password);
                bool isValid = this._argon2Wrapper.VerifyPassword(hash, password);
                Assert.True(isValid);
            }
        }
    }
}
