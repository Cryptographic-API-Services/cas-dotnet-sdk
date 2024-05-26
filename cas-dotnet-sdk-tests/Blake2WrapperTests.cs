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
            byte[] hash = this._wrapper.Hash512(message);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(message, hash);
        }

        [Fact]
        public void Blake2512HashBytesThreadpool()
        {
            byte[] message = Encoding.UTF8.GetBytes("MessageToHashWithBlake2");
            byte[] hash = this._wrapper.Hash512Threadpool(message);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(message, hash);
        }

        [Fact]
        public void Blake2256HashBytes()
        {
            byte[] message = Encoding.UTF8.GetBytes("MessageToHashWithBlake2256");
            byte[] hash = this._wrapper.Hash256(message);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(message, hash);
        }

        [Fact]
        public void Blake2256HashBytesThreadpool()
        {
            byte[] message = Encoding.UTF8.GetBytes("MessageToHashWithBlake2256");
            byte[] hash = this._wrapper.Hash256Threadpool(message);
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(message, hash);
        }

        [Fact]
        public void Blake2512VerifyBytes()
        {
            byte[] toHash = Encoding.UTF8.GetBytes("BadStuffToHash");
            byte[] hashed = this._wrapper.Hash512(toHash);
            bool isValid = this._wrapper.Verify512(hashed, toHash);
            Assert.True(isValid);
        }

        [Fact]
        public void Blake2512VerifyBytesThreadpool()
        {
            byte[] toHash = Encoding.UTF8.GetBytes("BadStuffToHash");
            byte[] hashed = this._wrapper.Hash512Threadpool(toHash);
            bool isValid = this._wrapper.Verify512Threadpool(hashed, toHash);
            Assert.True(isValid);
        }

        [Fact]
        public void Blake2256VerifyBytes()
        {
            byte[] toHash = Encoding.UTF8.GetBytes("BadStuffToHashFor256");
            byte[] hashed = this._wrapper.Hash256(toHash);
            bool isValid = this._wrapper.Verify256(hashed, toHash);
            Assert.True(isValid);
        }

        [Fact]
        public void Blake2256VerifyBytesThreadpool()
        {
            byte[] toHash = Encoding.UTF8.GetBytes("BadStuffToHashFor256");
            byte[] hashed = this._wrapper.Hash256Threadpool(toHash);
            bool isValid = this._wrapper.Verify256Threadpool(hashed, toHash);
            Assert.True(isValid);
        }
    }
}