using EasDotnetSdk.PasswordHash;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class SCryptWrapperTests
    {
        private readonly SCryptWrapper _scrypt;
        private readonly string _password;
        public SCryptWrapperTests()
        {
            this._scrypt = new SCryptWrapper();
            this._password = "TestPasswordToHash";
        }

        [Fact]
        public void HashPassword()
        {
            IntPtr hashedPasswordPtr = this._scrypt.HashPassword(this._password);
            string hashedPassword = Marshal.PtrToStringUTF8(hashedPasswordPtr);
            SCryptWrapper.free_cstring(hashedPasswordPtr);
            Assert.NotNull(hashedPassword);
            Assert.NotEqual(hashedPassword, this._password);
        }

        [Fact]
        public void VerifyPassword()
        {
            IntPtr hashedPasswordPtr = this._scrypt.HashPassword(this._password);
            string hashedPassword = Marshal.PtrToStringUTF8(hashedPasswordPtr);
            SCryptWrapper.free_cstring(hashedPasswordPtr);
            bool isValid = this._scrypt.VerifyPassword(this._password, hashedPassword);
            Assert.True(isValid);
        }
    }
}