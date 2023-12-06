using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class MD5WrapperTests
    {
        private MD5Wrapper _md5Wrapper { get; set; }
        public MD5WrapperTests()
        {
            _md5Wrapper = new MD5Wrapper();
        }

        [Fact]
        public void CreateHash()
        {
            string dataToHash = "HashThisData";
            IntPtr hashedPtr = this._md5Wrapper.Hash(dataToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            MD5Wrapper.free_cstring(hashedPtr);
            Assert.NotEmpty(hashed);
            Assert.NotNull(hashed);
            Assert.NotEqual(dataToHash, hashed);
        }

        [Fact]
        public async Task VerifyHash()
        {
            string dataToHash = "HashThisData";
            IntPtr hashedPtr = this._md5Wrapper.Hash(dataToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            MD5Wrapper.free_cstring(hashedPtr);
            Assert.NotEmpty(hashed);
            Assert.NotNull(hashed);
            Assert.NotEqual(dataToHash, hashed);
            Assert.True(this._md5Wrapper.Verify(hashed, dataToHash));
        }
    }
}
