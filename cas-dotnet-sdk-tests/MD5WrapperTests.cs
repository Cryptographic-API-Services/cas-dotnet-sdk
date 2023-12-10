using CasDotnetSdk.Hashers;

namespace CasDotnetSdkTests.Tests
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
            string hashed = this._md5Wrapper.Hash(dataToHash);
            Assert.NotEmpty(hashed);
            Assert.NotNull(hashed);
            Assert.NotEqual(dataToHash, hashed);
        }

        [Fact]
        public async Task VerifyHash()
        {
            string dataToHash = "HashThisData";
            string hashed = this._md5Wrapper.Hash(dataToHash);
            Assert.NotEmpty(hashed);
            Assert.NotNull(hashed);
            Assert.NotEqual(dataToHash, hashed);
            Assert.True(this._md5Wrapper.Verify(hashed, dataToHash));
        }
    }
}
