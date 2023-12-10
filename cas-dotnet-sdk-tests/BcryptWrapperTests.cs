using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers;
using System.Runtime.InteropServices;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class BcryptWrapperTests
    {
        private BcryptWrapper _cryptWrapper { get; set; }
        private readonly OperatingSystemDeterminator _operatingSystem;
        private string _testPassword { get; set; }

        public BcryptWrapperTests()
        {
            this._cryptWrapper = new BcryptWrapper();
            this._testPassword = "testPassword";
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void HashPassword()
        {
            string hashed = this._cryptWrapper.HashPassword(this._testPassword);
            Assert.NotEqual(hashed, this._testPassword);
        }

        [Fact]
        public async Task Verify()
        {
            string hashedPassword = this._cryptWrapper.HashPassword(this._testPassword);
            Assert.True(this._cryptWrapper.Verify(hashedPassword, this._testPassword));
        }
    }
}