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
        public void HashPasswordWithParameters()
        {
            uint cost = 12;
            string hashed = this._cryptWrapper.HashPasswordWithParameters(this._testPassword, cost);
            Assert.NotEqual(hashed, this._testPassword);
        }

        [Theory]
        [InlineData(10u)]
        [InlineData(16u)]
        public void HashPasswordWithParametersAcceptsBounds(uint cost)
        {
            string hashed = this._cryptWrapper.HashPasswordWithParameters(this._testPassword, cost);
            Assert.StartsWith($"$2b${cost}$", hashed);
            Assert.True(this._cryptWrapper.Verify(hashed, this._testPassword));
        }

        // cost is a uint, so negative values can't be passed.
        [Theory]
        [InlineData(0u)]
        [InlineData(9u)]
        [InlineData(17u)]
        [InlineData(31u)]
        [InlineData(uint.MaxValue)]
        public void HashPasswordWithParametersRejectsOutOfRange(uint cost)
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => this._cryptWrapper.HashPasswordWithParameters(this._testPassword, cost));
            Assert.Equal("cost", ex.ParamName);
        }

        [Fact]
        public async Task Verify()
        {
            string hashedPassword = this._cryptWrapper.HashPassword(this._testPassword);
            Assert.True(this._cryptWrapper.Verify(hashedPassword, this._testPassword));
        }

        [Fact]
        public void AcceptsPasswordOf72Bytes()
        {
            string password = new string('a', 72);
            string hashed = this._cryptWrapper.HashPasswordWithParameters(password, 10);
            Assert.True(this._cryptWrapper.Verify(hashed, password));
            Assert.False(this._cryptWrapper.Verify(hashed, new string('a', 71)));

            // 36 two-byte characters are 72 UTF-8 bytes.
            string multiByte = new string('é', 36);
            Assert.True(this._cryptWrapper.Verify(this._cryptWrapper.HashPasswordWithParameters(multiByte, 10), multiByte));
        }

        [Fact]
        public void RejectsPasswordOver72Bytes()
        {
            string hashed = this._cryptWrapper.HashPasswordWithParameters(new string('a', 72), 10);
            string tooLong = new string('a', 73);
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.HashPassword(tooLong));
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.HashPasswordWithParameters(tooLong, 10));
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.Verify(hashed, tooLong));

            // 37 characters, but 74 UTF-8 bytes: the limit counts bytes.
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.HashPassword(new string('é', 37)));
        }

        [Fact]
        public void EmbeddedNulIsHashed()
        {
            string hashWithNul = this._cryptWrapper.HashPasswordWithParameters("abc\0x", 10);
            string hashWithoutNul = this._cryptWrapper.HashPasswordWithParameters("abc", 10);
            Assert.True(this._cryptWrapper.Verify(hashWithNul, "abc\0x"));
            Assert.False(this._cryptWrapper.Verify(hashWithNul, "abc"));
            Assert.False(this._cryptWrapper.Verify(hashWithoutNul, "abc\0x"));
        }

        [Fact]
        public void RejectsNullOrEmptyPassword()
        {
            string hashed = this._cryptWrapper.HashPasswordWithParameters(this._testPassword, 10);
            Assert.Throws<ArgumentNullException>(() => this._cryptWrapper.HashPassword(null!));
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.HashPassword(""));
            Assert.Throws<ArgumentNullException>(() => this._cryptWrapper.HashPasswordWithParameters(null!, 12));
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.HashPasswordWithParameters("", 12));
            Assert.Throws<ArgumentNullException>(() => this._cryptWrapper.Verify(hashed, null!));
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.Verify(hashed, ""));
            Assert.Throws<ArgumentNullException>(() => this._cryptWrapper.Verify(null!, this._testPassword));
            Assert.Throws<ArgumentException>(() => this._cryptWrapper.Verify("", this._testPassword));
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
            Assert.True(wrapper.Verify(hahed, badPassword));
        }
    }
}
