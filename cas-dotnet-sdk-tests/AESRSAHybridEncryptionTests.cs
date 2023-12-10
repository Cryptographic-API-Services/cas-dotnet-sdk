using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Symmetric;
using Xunit;
using static CasDotnetSdk.Asymmetric.RSAWrapper;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdkTests.Tests
{
    public class AESRSAHybridEncryptionTests
    {
        private readonly AESWrapper _aesWrapper;
        private readonly RSAWrapper _rsaWrapper;

        public AESRSAHybridEncryptionTests()
        {
            this._aesWrapper = new AESWrapper();
            this._rsaWrapper = new RSAWrapper();
        }

        [Fact]
        public void AESRSAHybridEncrypt()
        {
            string dataToEncrypt = "DataToEncrypt";
            string nonce = "TestingNonce";
            RsaKeyPairResult keyPair = this._rsaWrapper.GetKeyPair(2048);
            AesEncryptResult encryptedResult = this._aesWrapper.Aes256Encrypt(nonce, dataToEncrypt);
            string encryptedAesKey = this._rsaWrapper.RsaEncrypt(keyPair.PublicKey, encryptedResult.Key);
            Assert.NotEqual(encryptedResult.Key, encryptedAesKey);
            Assert.NotEqual(dataToEncrypt, encryptedResult.CipherText);
        }

        [Fact]
        public void AESRSAHybridDecrypt()
        {
            string dataToEncrypt = "DataToEncrypt";
            string nonce = "TestingNonce";
            RsaKeyPairResult keyPair = this._rsaWrapper.GetKeyPair(2048);
            AesEncryptResult encryptedResult = this._aesWrapper.Aes256Encrypt(nonce, dataToEncrypt);
            string encryptedAesKey = this._rsaWrapper.RsaEncrypt(keyPair.PublicKey, encryptedResult.Key);
            string decryptedAesKey = this._rsaWrapper.RsaDecrypt(keyPair.PrivateKey, encryptedAesKey);
            string decrypted = this._aesWrapper.Aes256Decrypt(nonce, decryptedAesKey, encryptedResult.CipherText);
            Assert.Equal(decrypted, dataToEncrypt);
        }
    }
}