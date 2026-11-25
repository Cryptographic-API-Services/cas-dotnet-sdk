using CasDotnetSdk.PasswordHashers;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class SCryptWrapperTests
    {
        private readonly SCryptWrapper _scrypt;
        private readonly string _password;
        public SCryptWrapperTests()
        {
            this._scrypt = new SCryptWrapper();
            this._password = "TestPasswordToHash";
        }

        [Fact]
        public void HashPassword()
        {
            string hashedPassword = this._scrypt.HashPassword(this._password);
            Assert.NotNull(hashedPassword);
            Assert.NotEqual(hashedPassword, this._password);
        }

        [Fact]
        public void HashPasswordWithParameters()
        {
            string hashedPassword = this._scrypt.HashPasswordWithParameters(this._password, cpuCost: 16, blockSize: 8, parallelism: 2);
            Assert.NotNull(hashedPassword);
            Assert.NotEqual(hashedPassword, this._password);
        }

        [Theory]
        [InlineData(10, 8, 1)]
        [InlineData(20, 2, 1)] // 256 MiB; cpuCost 20 needs blockSize >= 2
        [InlineData(10, 1, 1)]
        [InlineData(15, 1, 1)] // the largest cpuCost blockSize 1 allows
        [InlineData(10, 32, 1)]
        [InlineData(10, 1, 16)]
        public void HashPasswordWithParametersAcceptsBounds(int cpuCost, int blockSize, int parallelism)
        {
            string hashedPassword = this._scrypt.HashPasswordWithParameters(this._password, cpuCost, blockSize, parallelism);
            Assert.Contains($"ln={cpuCost},r={blockSize},p={parallelism}", hashedPassword);
            Assert.True(this._scrypt.Verify(hashedPassword, this._password));
        }

        [Theory]
        [InlineData(9, 8, 1, "cpuCost")]
        [InlineData(21, 8, 1, "cpuCost")]
        [InlineData(-1, 8, 1, "cpuCost")]
        [InlineData(256, 8, 1, "cpuCost")] // used to truncate to log2(N) = 0
        [InlineData(264, 8, 1, "cpuCost")] // used to truncate to log2(N) = 8
        [InlineData(16, 1, 1, "cpuCost")] // scrypt needs cpuCost < 16 * blockSize
        [InlineData(10, 0, 1, "blockSize")]
        [InlineData(10, 33, 1, "blockSize")]
        [InlineData(10, -1, 1, "blockSize")]
        [InlineData(10, 8, 0, "parallelism")]
        [InlineData(10, 8, 17, "parallelism")]
        [InlineData(10, 8, -1, "parallelism")]
        public void HashPasswordWithParametersRejectsOutOfRange(int cpuCost, int blockSize, int parallelism, string paramName)
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => this._scrypt.HashPasswordWithParameters(this._password, cpuCost, blockSize, parallelism));
            Assert.Equal(paramName, ex.ParamName);
        }

        [Fact]
        public void VerifyPassword()
        {
            string hashedPassword = this._scrypt.HashPassword(this._password);
            bool isValid = this._scrypt.Verify(hashedPassword, this._password);
            Assert.True(isValid);
        }

        [Fact]
        public void EmbeddedNulIsHashed()
        {
            string hashWithNul = this._scrypt.HashPasswordWithParameters("abc\0x", cpuCost: 10);
            string hashWithoutNul = this._scrypt.HashPasswordWithParameters("abc", cpuCost: 10);
            Assert.True(this._scrypt.Verify(hashWithNul, "abc\0x"));
            Assert.False(this._scrypt.Verify(hashWithNul, "abc"));
            Assert.False(this._scrypt.Verify(hashWithoutNul, "abc\0x"));
        }

        [Fact]
        public void RejectsNullOrEmptyPassword()
        {
            string hashed = this._scrypt.HashPasswordWithParameters(this._password, cpuCost: 10);
            Assert.Throws<ArgumentNullException>(() => this._scrypt.HashPassword(null!));
            Assert.Throws<ArgumentException>(() => this._scrypt.HashPassword(""));
            Assert.Throws<ArgumentNullException>(() => this._scrypt.HashPasswordWithParameters(null!));
            Assert.Throws<ArgumentException>(() => this._scrypt.HashPasswordWithParameters(""));
            Assert.Throws<ArgumentNullException>(() => this._scrypt.Verify(hashed, null!));
            Assert.Throws<ArgumentException>(() => this._scrypt.Verify(hashed, ""));
            Assert.Throws<ArgumentNullException>(() => this._scrypt.Verify(null!, this._password));
            Assert.Throws<ArgumentException>(() => this._scrypt.Verify("", this._password));
        }

        [Fact]
        public void FactoryTest()
        {
            IPasswordHasherBase wrapper = PasswordHasherFactory.Get(PasswordHasherType.SCrypt);
            string badPassword = "Don't DO It";
            string hahed = wrapper.HashPassword(badPassword);
            Assert.NotNull(wrapper);
            Assert.NotEqual(badPassword, hahed);
            Assert.Equal(typeof(SCryptWrapper), wrapper.GetType());
            Assert.True(wrapper.Verify(hahed, badPassword));
        }

    }
}
