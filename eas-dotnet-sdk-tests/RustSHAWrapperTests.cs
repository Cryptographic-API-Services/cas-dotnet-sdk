using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class SHAWrapperTests
    {
        private SHAWrapper _wrapper;
        private string _testString;
        public SHAWrapperTests()
        {
            this._wrapper = new SHAWrapper();
            this._testString = "Test hash to hash";
        }

        [Fact]
        public void SHA512Hash()
        {
            IntPtr hashedPtr = this._wrapper.SHA512HashString(this._testString);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            SHAWrapper.free_cstring(hashedPtr);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.NotEqual(hashed, this._testString);
        }

        [Fact]
        public async Task SHA256Hash()
        {
            IntPtr hashedPtr = this._wrapper.SHA256HashString(this._testString);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            SHAWrapper.free_cstring(hashedPtr);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.NotEqual(hashed, this._testString);
        }
    }
}
