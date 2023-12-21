using CasDotnetSdk.PasswordHashers;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Argon2WrapperTests
    {
        private Argon2Wrappper _argon2Wrapper;

        public Argon2WrapperTests()
        {
            this._argon2Wrapper = new Argon2Wrappper();
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

        //[Fact]
        //public void VerifyThread()
        //{
        //    string password = "TestPasswordToVerify";
        //    string hash = this._argon2Wrapper.HashPasswordThread(password);
        //    bool isValid = this._argon2Wrapper.VerifyPasswordThread(hash, password);
        //    Assert.True(isValid);
        //}
    }
}
