using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Symmetric;
using Xunit;
using static CasDotnetSdk.Hybrid.AESRSAHybridWrapper;

namespace CasDotnetSdkTests.Tests
{
    public class AESRSAHybridEncryptionTests
    {
        private readonly AESWrapper _aesWrapper;
        private readonly AESRSAHybridWrapper _hybridWrapper;

        public AESRSAHybridEncryptionTests()
        {
            this._aesWrapper = new AESWrapper();
            this._hybridWrapper = new AESRSAHybridWrapper();
        }

        [Fact]
        public void AESRSAHybridEncrypt()
        {
            string dataToEncrypt = "DataToEncrypt";
            string nonce = this._aesWrapper.GenerateAESNonce();
            AESRSAHybridEncryptResult result = this._hybridWrapper.AES256RSAHybridEncrypt(dataToEncrypt, nonce, 2048, 256);
            Assert.NotEqual(dataToEncrypt, result.CipherText);
        }

        [Fact]
        public void AESRSAHybridDecrypt()
        {
            string dataToEncrypt = "DataToEncrypt";
            string nonce = this._aesWrapper.GenerateAESNonce();
            AESRSAHybridEncryptResult result = this._hybridWrapper.AES256RSAHybridEncrypt(dataToEncrypt, nonce, 2048, 256);
            string decrypted = this._hybridWrapper.AES256RSAHybridDecrypt(result);
            Assert.Equal(decrypted, dataToEncrypt);
        }
    }
}