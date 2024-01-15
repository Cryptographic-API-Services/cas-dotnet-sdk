using CasDotnetSdk.PasswordHashers;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Argon2WrapperTests
    {
        private Argon2Wrapper _argon2Wrapper;

        public Argon2WrapperTests()
        {
            this._argon2Wrapper = new Argon2Wrapper();
        }

        [Fact]
        public void HashPassword()
        {
            string password = "DoNotUSETHISPASS@!";
            string hash = this._argon2Wrapper.HashPassword(password);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void HashPasswordsThread()
        {
            string[] arrayOfPass = new string[] { "testing", "another password" };
            string[] hash = this._argon2Wrapper.HashPasswordsThread(arrayOfPass);
            Assert.True(hash.Length == arrayOfPass.Length);
        }

        [Fact]
        public void Verify()
        {
            string password = "TestPasswordToVerify";
            string hash = this._argon2Wrapper.HashPassword(password);
            bool isValid = this._argon2Wrapper.VerifyPassword(hash, password);
            Assert.True(isValid);
        }

        [Fact]
        public void FactoryTest()
        {
            IPasswordHasherBase wrapper = PasswordHasherFactory.Get(PasswordHasherType.Argon2);
            string badPassword = "Don't DO It";
            string hahed = wrapper.HashPassword(badPassword);
            Assert.NotNull(wrapper);
            Assert.NotEqual(badPassword, hahed);
            Assert.Equal(typeof(Argon2Wrapper), wrapper.GetType());
        }
    }
}
