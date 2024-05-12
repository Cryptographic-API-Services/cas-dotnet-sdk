using CasDotnetSdk.PasswordHashers;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class BcryptWrapperTests
    {
        private BcryptWrapper _cryptWrapper { get; set; }
        private string _testPassword { get; set; }

        public BcryptWrapperTests()
        {
            this._cryptWrapper = new BcryptWrapper();
            this._testPassword = "testPassword";
        }

        [Fact]
        public void HashPassword()
        {
            string hashed = this._cryptWrapper.HashPassword(this._testPassword);
            Assert.NotEqual(hashed, this._testPassword);
        }

        [Fact]
        public void HashPasswordThreadPool()
        {
            string hashed = this._cryptWrapper.HashPasswordThreadPool(this._testPassword);
            Assert.NotEqual(hashed, this._testPassword);
        }

        [Fact]
        public async Task Verify()
        {
            string hashedPassword = this._cryptWrapper.HashPassword(this._testPassword);
            Assert.True(this._cryptWrapper.Verify(hashedPassword, this._testPassword));
        }

        [Fact]
        public void FactoryTest()
        {
            IPasswordHasherBase wrapper = PasswordHasherFactory.Get(PasswordHasherType.BCrypt);
            string badPassword = "Don't DO It";
            string hahed = wrapper.HashPassword(badPassword);
            Assert.NotNull(wrapper);
            Assert.NotEqual(badPassword, hahed);
            Assert.Equal(typeof(BcryptWrapper), wrapper.GetType());
        }
    }
}