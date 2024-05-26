using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Hybrid.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class HybridEncryptionTests
    {
        private readonly HybridEncryptionWrapper _hybridEncryptionWrapper;
        public HybridEncryptionTests()
        {
            this._hybridEncryptionWrapper = new HybridEncryptionWrapper();
        }

        [Fact]
        public void Encrypt()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Encrypting this stuff is fun along with the textbooks");
            AESRSAHybridInitializer initializer = new AESRSAHybridInitializer(128, 2048);
            AESRSAHybridEncryptResult result = this._hybridEncryptionWrapper.EncryptAESRSAHybrid(dataToEncrypt, initializer);
            Assert.NotEmpty(result.EncryptedAesKey);
            Assert.NotNull(result.AesType);
            Assert.NotEmpty(result.AesNonce);
            Assert.NotNull(result.CipherText);
        }

        [Fact]
        public void EncryptThreadpool()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("Encrypting this stuff is fun along with the textbooks");
            AESRSAHybridInitializer initializer = new AESRSAHybridInitializer(128, 2048);
            AESRSAHybridEncryptResult result = this._hybridEncryptionWrapper.EncryptAESRSAHybridThreadpool(dataToEncrypt, initializer);
            Assert.NotEmpty(result.EncryptedAesKey);
            Assert.NotNull(result.AesType);
            Assert.NotEmpty(result.AesNonce);
            Assert.NotNull(result.CipherText);
        }

        [Fact]
        public void Decrypt()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("What is that? A New Router that I see?");
            // Initializer creates our AES key, AES Nonce, and RSA Key Pair for us.
            AESRSAHybridInitializer initializer = new AESRSAHybridInitializer(256, 4096);
            AESRSAHybridEncryptResult result = this._hybridEncryptionWrapper.EncryptAESRSAHybridThreadpool(dataToEncrypt, initializer);
            byte[] plaintext = this._hybridEncryptionWrapper.DecryptAESRSAHybridThreadpool(initializer.RsaKeyPair.PrivateKey, result);
            Assert.Equal(dataToEncrypt, plaintext);
        }

        [Fact]
        public void DecryptThreadpool()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("What is that? A New Router that I see?");
            // Initializer creates our AES key, AES Nonce, and RSA Key Pair for us.
            AESRSAHybridInitializer initializer = new AESRSAHybridInitializer(256, 4096);
            AESRSAHybridEncryptResult result = this._hybridEncryptionWrapper.EncryptAESRSAHybridThreadpool(dataToEncrypt, initializer);
            byte[] plaintext = this._hybridEncryptionWrapper.DecryptAESRSAHybridThreadpool(initializer.RsaKeyPair.PrivateKey, result);
            Assert.Equal(dataToEncrypt, plaintext);
        }
    }
}
