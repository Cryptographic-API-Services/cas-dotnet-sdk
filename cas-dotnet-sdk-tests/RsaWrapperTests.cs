using System.Text;
using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;
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
        public async Task RsaSignBytes()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(4096);
            byte[] signature = this._RSAWrapper.RsaSignWithKeyBytes(keys.PrivateKey, dataToSign);
            Assert.NotEqual(dataToSign, signature);
        }

        [Fact]
        public async Task RsaSignBytesThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPairThreadPool(2048);
            byte[] signature = this._RSAWrapper.RsaSignWithKeyBytesThreadpool(keys.PrivateKey, dataToSign);
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

        [Fact]
        public async Task RsaVerifyBytesThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPairThreadPool(1024);
            byte[] signature = this._RSAWrapper.RsaSignWithKeyBytesThreadpool(keys.PrivateKey, dataToSign);
            bool isValid = this._RSAWrapper.RsaVerifyBytesThreadpool(keys.PublicKey, dataToSign, signature);
            Assert.True(isValid);
        }
    }
}