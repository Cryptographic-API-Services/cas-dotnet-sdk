using EasDotnetSdk.PasswordHash;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class BcryptWrapperTests
    {
        private BcryptWrapper _cryptWrapper { get; set; }
        private string _testPassword { get; set; }

        public BcryptWrapperTests()
        {
            this._cryptWrapper = new BcryptWrapper();
            this._testPassword = "testPassword";
        }

        [Fact]
        public void HashPassword()
        {
            IntPtr hashedPasswordPtr = this._cryptWrapper.HashPassword(this._testPassword);
            string hashedPassword = Marshal.PtrToStringUTF8(hashedPasswordPtr);
            BcryptWrapper.free_cstring(hashedPasswordPtr);
            Assert.NotEqual(hashedPassword, this._testPassword);
        }

        [Fact]
        public async Task Verify()
        {
            IntPtr hashedPasswordPtr = this._cryptWrapper.HashPassword(this._testPassword);
            string hashedPassword = Marshal.PtrToStringUTF8(hashedPasswordPtr);
            BcryptWrapper.free_cstring(hashedPasswordPtr);
            Assert.True(this._cryptWrapper.Verify(hashedPassword, this._testPassword));
        }
    }
}
