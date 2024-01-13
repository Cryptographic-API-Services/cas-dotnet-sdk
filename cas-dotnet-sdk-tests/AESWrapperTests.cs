using CasDotnetSdk.Symmetric;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class AESWrapperTests
    {
        private readonly AESWrapper _aESWrapper;

        public AESWrapperTests()
        {
            this._aESWrapper = new AESWrapper();
        }

        [Fact]
        public void Aes128BytesEncrypt()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string key = this._aESWrapper.Aes128Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes128BytesEncrypt(nonceKey, key, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes128Key()
        {
            string key = this._aESWrapper.Aes128Key();
            Assert.True(!string.IsNullOrEmpty(key));
        }

        [Fact]
        public void Aes128BytesDecrypt()
        {

            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string key = this._aESWrapper.Aes128Key();
            byte[] dataToEncrypt = Encoding.ASCII.GetBytes("Thisisthedatathatne1233123123123123123edstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes128BytesEncrypt(nonceKey, key, dataToEncrypt);
            byte[] decrypted = this._aESWrapper.Aes128BytesDecrypt(nonceKey, key, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public void Aes256Key()
        {
            string key = this._aESWrapper.Aes256Key();
            Assert.True(!string.IsNullOrEmpty(key));
        }

        [Fact]
        public void Aes256BytesEncrypt()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string key = this._aESWrapper.Aes256Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes256EncryptBytes(nonceKey, key, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes256BytesDecrypt()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string key = this._aESWrapper.Aes256Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes256EncryptBytes(nonceKey, key, dataToEncrypt);
            byte[] decrypted = this._aESWrapper.Aes256DecryptBytes(nonceKey, key, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }
    }
}
