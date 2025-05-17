using System.Text;
using CasDotnetSdk.PasswordHashers;
using CasDotnetSdk.Symmetric;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Argon2WrapperTests
    {
        private Argon2Wrapper _argon2Wrapper;
        private AESWrapper _aesWrapper;

        public Argon2WrapperTests()
        {
            this._argon2Wrapper = new Argon2Wrapper();
            this._aesWrapper = new AESWrapper();
        }

        [Fact]
        public void HashPassword()
        {
            string password = "DoNotUSETHISPASS@!";
            string hash = this._argon2Wrapper.HashPassword(password);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void HashPasswordThreadPool()
        {
            string password = "DoNotUSETHISPASS@!";
            string hash = this._argon2Wrapper.HashPasswordThreadPool(password);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Verify()
        {
            string password = "TestPasswordToVerify";
            string hash = this._argon2Wrapper.HashPassword(password);
            bool isValid = this._argon2Wrapper.Verify(hash, password);
            Assert.True(isValid);
        }

        [Fact]
        public void VerifyThreadpool()
        {
            string password = "TestPasswordToVerify";
            string hash = this._argon2Wrapper.HashPasswordThreadPool(password);
            bool isValid = this._argon2Wrapper.VerifyThreadPool(hash, password);
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

        [Fact]
        public void DeriveAES128Key()
        {
            string password = "kdfsAreFun";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("LetsEncryptThisWord");
            byte[] key = this._argon2Wrapper.DeriveAES128Key(password);
            byte[] aesNonce = this._aesWrapper.GenerateAESNonce();
            byte[] encrypted = this._aesWrapper.Aes128Encrypt(aesNonce, key, dataToEncrypt);
            byte[] decrypted = this._aesWrapper.Aes128Decrypt(aesNonce, key, encrypted);
            Assert.NotNull(decrypted);
            Assert.NotNull(encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
        }

        [Fact]
        public void DeriveAES256Key()
        {
            string password = "kdfsAreFun";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("LetsEncrypt345343455ThisWor456d");
            byte[] key = this._argon2Wrapper.DeriveAES256Key(password);
            byte[] aesNonce = this._aesWrapper.GenerateAESNonce();
            byte[] encrypted = this._aesWrapper.Aes256Encrypt(aesNonce, key, dataToEncrypt);
            byte[] decrypted = this._aesWrapper.Aes256Decrypt(aesNonce, key, encrypted);
            Assert.NotNull(decrypted);
            Assert.NotNull(encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
        }
    }
}
