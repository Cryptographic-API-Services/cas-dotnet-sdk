using EasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class HmacWrapperTests
    {
        private HmacWrapper _hmacWrapper { get; set; }
        private readonly OperatingSystemDeterminator _operatingSystem;
        public HmacWrapperTests()
        {
            this._hmacWrapper = new HmacWrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void HmacSign()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string key = "HmacKey";
                string message = "message to sign";
                IntPtr signaturePtr = this._hmacWrapper.HmacSign(key, message);
                string signature = Marshal.PtrToStringAnsi(signaturePtr);
                HmacWrapper.free_cstring(signaturePtr);
                Assert.NotNull(signature);
                Assert.NotEqual(message, signature);
            }
        }

        [Fact]
        public void HmacVerify()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string key = "HmacKey";
                string message = "message to sign";
                IntPtr signaturePtr = this._hmacWrapper.HmacSign(key, message);
                string signature = Marshal.PtrToStringAnsi(signaturePtr);
                bool isValid = this._hmacWrapper.HmacVerify(key, message, signature);
                HmacWrapper.free_cstring(signaturePtr);
                Assert.Equal(true, isValid);
            }
        }
    }
}
