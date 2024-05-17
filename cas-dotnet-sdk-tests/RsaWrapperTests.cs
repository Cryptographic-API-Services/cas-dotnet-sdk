using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class RSAWrapperTests
    {
        private readonly RSAWrapper _RSAWrapper;
        private readonly RsaKeyPairResult _encryptDecryptKeyPair;
        public RSAWrapperTests()
        {
            this._RSAWrapper = new RSAWrapper();
            this._encryptDecryptKeyPair = this._RSAWrapper.GetKeyPair(4096);
        }

        [Fact]
        public void CreateKeyPair()
        {
            RsaKeyPairResult keyPair = this._RSAWrapper.GetKeyPair(4096);
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);
        }

        [Fact]
        public void CreateKeyPairThreadpool()
        {
            RsaKeyPairResult keyPair = this._RSAWrapper.GetKeyPair(1024);
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);
        }

        [Fact]
        public void RsaEncryptBytes()
        {
            byte[] dataToEncrypted = Encoding.UTF8.GetBytes("Testing Stuff TO Encrypt");
            byte[] encryped = this._RSAWrapper.RsaEncryptBytes(this._encryptDecryptKeyPair.PublicKey, dataToEncrypted);
            Assert.NotEqual(dataToEncrypted, encryped);
        }

        [Fact]
        public void RsaEncryptBytesThreadpool()
        {
            byte[] dataToEncrypted = Encoding.UTF8.GetBytes("Testing Stuff TO Encrypt");
            byte[] encryped = this._RSAWrapper.RsaEncryptBytesThreadpool(this._encryptDecryptKeyPair.PublicKey, dataToEncrypted);
            Assert.NotEqual(dataToEncrypted, encryped);
        }

        [Fact]
        public void RsaDecryptBytesThreadpool()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("EncryptingStuffIsFun");
            byte[] encrypted = this._RSAWrapper.RsaEncryptBytesThreadpool(this._encryptDecryptKeyPair.PublicKey, dataToEncrypt);
            byte[] decrypted = this._RSAWrapper.RsaDecryptBytesThreadpool(this._encryptDecryptKeyPair.PrivateKey, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public void RsaDecryptBytes()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("EncryptingStuffIsFun");
            byte[] encrypted = this._RSAWrapper.RsaEncryptBytes(this._encryptDecryptKeyPair.PublicKey, dataToEncrypt);
            byte[] decrypted = this._RSAWrapper.RsaDecryptBytes(this._encryptDecryptKeyPair.PrivateKey, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public async Task RsaSignBytes()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(4096);
            byte[] signature = this._RSAWrapper.RsaSignWithKeyBytes(keys.PrivateKey, dataToSign);
            Assert.NotEqual(dataToSign, signature);
        }

        [Fact]
        public async Task RsaVerifyBytes()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(4096);
            byte[] signature = this._RSAWrapper.RsaSignWithKeyBytes(keys.PrivateKey, dataToSign);
            bool isValid = this._RSAWrapper.RsaVerifyBytes(keys.PublicKey, dataToSign, signature);
            Assert.True(isValid);
        }
    }
}