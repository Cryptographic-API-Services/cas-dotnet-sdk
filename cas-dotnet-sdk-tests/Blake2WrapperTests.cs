using CasDotnetSdk.Hashers;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Blake2WrapperTests
    {
        private readonly Blake2Wrapper _wrapper;

        public Blake2WrapperTests()
        {
            this._wrapper = new Blake2Wrapper();
        }

        [Fact]
        public void Blake2512HashBytes()
        {
            byte[] message = Encoding.UTF8.GetBytes("MessageToHashWithBlake2");
            byte[] hash = this._wrapper.Blake2512Bytes(message);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(message, hash);
        }

        [Fact]
        public void Blake2256HashBytes()
        {
            byte[] message = Encoding.UTF8.GetBytes("MessageToHashWithBlake2256");
            byte[] hash = this._wrapper.Blake2256Bytes(message);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(message, hash);
        }

        [Fact]
        public void Blake2512VerifyBytes()
        {
            byte[] toHash = Encoding.UTF8.GetBytes("BadStuffToHash");
            byte[] hashed = this._wrapper.Blake2512Bytes(toHash);
            bool isValid = this._wrapper.Blake2512VerifyBytes(hashed, toHash);
            Assert.True(isValid);
        }

        [Fact]
        public void Blake2256VerifyBytes()
        {
            byte[] toHash = Encoding.UTF8.GetBytes("BadStuffToHashFor256");
            byte[] hashed = this._wrapper.Blake2256Bytes(toHash);
            bool isValid = this._wrapper.Blake2256BytesVerify(hashed, toHash);
            Assert.True(isValid);
        }
    }
}