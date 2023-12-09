using EasDotnetSdk.Helpers;
using EasDotnetSdk.PasswordHashers;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class SCryptWrapperTests
    {
        private readonly SCryptWrapper _scrypt;
        private readonly string _password;
        private readonly OperatingSystemDeterminator _operatingSystem;
        public SCryptWrapperTests()
        {
            this._scrypt = new SCryptWrapper();
            this._password = "TestPasswordToHash";
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
                string hashedPassword = this._scrypt.HashPassword(this._password);
                Assert.NotNull(hashedPassword);
                Assert.NotEqual(hashedPassword, this._password);
            }
        }

        [Fact]
        public void VerifyPassword()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string hashedPassword = this._scrypt.HashPassword(this._password);
                bool isValid = this._scrypt.VerifyPassword(this._password, hashedPassword);
                Assert.True(isValid);
            }
        }
    }
}