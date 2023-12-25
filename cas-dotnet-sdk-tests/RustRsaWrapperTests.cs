using CasDotnetSdk.Asymmetric;
using System.Text;
using Xunit;
using static CasDotnetSdk.Asymmetric.RSAWrapper;

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
        public void RsaEncrypt()
        {
            string dataToEncrypt = "EncryptingStuffIsFun";
            string encrypted = this._RSAWrapper.RsaEncrypt(this._encryptDecryptKeyPair.PublicKey, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void RsaEncryptBytes()
        {
            byte[] dataToEncrypted = Encoding.UTF8.GetBytes("Testing Stuff TO Encrypt");
            byte[] encryped = this._RSAWrapper.RsaEncryptBytes(this._encryptDecryptKeyPair.PublicKey, dataToEncrypted);
            Assert.NotEqual(dataToEncrypted, encryped);
        }

        [Fact]
        public void RsaDecrypt()
        {
            string dataToEncrypt = "EncryptingStuffIsFun";
            string encrypted = this._RSAWrapper.RsaEncrypt(this._encryptDecryptKeyPair.PublicKey, dataToEncrypt);
            string decrypted = this._RSAWrapper.RsaDecrypt(this._encryptDecryptKeyPair.PrivateKey, encrypted);
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
        public async void RsaSign()
        {
            string dataToSign = "Sign This Data For Me";
            RsaSignResult result = this._RSAWrapper.RsaSign(dataToSign, 4096);
            Assert.NotNull(result.PublicKey);
            Assert.NotNull(result.Signature);
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
        public async void RsaVerify()
        {
            string dataToSign = "Data That Needs To Be Verified";
            RsaSignResult result = this._RSAWrapper.RsaSign(dataToSign, 4096);
            bool isValid = this._RSAWrapper.RsaVerify(result.PublicKey, dataToSign, result.Signature);
            Assert.Equal(true, isValid);
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

        [Fact]
        public async void RsaSignWithKey()
        {
            string dataToSign = "This data needs to be signed now";
            RsaKeyPairResult keyPair = this._RSAWrapper.GetKeyPair(2048);
            string signature = this._RSAWrapper.RsaSignWithKey(keyPair.PrivateKey, dataToSign);
            Assert.NotNull(signature);
            Assert.NotEqual(dataToSign, signature);
        }
    }
}