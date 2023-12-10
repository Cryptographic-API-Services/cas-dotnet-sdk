using CasDotnetSdk.Hashers;

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
        public void SHA512Hash()
        {
            string hashed = this._wrapper.SHA512HashString(this._testString);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.NotEqual(hashed, this._testString);
        }

        [Fact]
        public async Task SHA256Hash()
        {
            string hashed = this._wrapper.SHA256HashString(this._testString);
            Assert.NotNull(hashed);
            Assert.NotEmpty(hashed);
            Assert.NotEqual(hashed, this._testString);
        }
    }
}
