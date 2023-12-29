using CasDotnetSdk.Hashers;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
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
        public void SHA512HashBytes()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.SHA512HashBytes(data);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.True(hashed.Length > 0);
        }

        [Fact]
        public void SHA256HashBytes()
        {
            byte[] data = Encoding.UTF8.GetBytes(this._testString);
            byte[] hashed = this._wrapper.SHA256HashBytes(data);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.True(hashed.Length > 0);
        }
    }
}
