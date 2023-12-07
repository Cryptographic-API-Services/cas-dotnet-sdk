using EasDotnetSdk.Hashers;
using EasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class SHAWrapperTests
    {
        private SHAWrapper _wrapper;
        private string _testString;
        private readonly OperatingSystemDeterminator _operatingSystem;
        public SHAWrapperTests()
        {
            this._wrapper = new SHAWrapper();
            this._testString = "Test hash to hash";
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void SHA512Hash()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr hashedPtr = this._wrapper.SHA512HashString(this._testString);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHAWrapper.free_cstring(hashedPtr);
                Assert.NotNull(hashed);
                Assert.NotEmpty(hashed);
                Assert.NotEqual(hashed, this._testString);
            }
        }

        [Fact]
        public async Task SHA256Hash()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
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
}
