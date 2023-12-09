using EasDotnetSdk.Asymmetric;
using EasDotnetSdk.Helpers;
using EasDotnetSdk.Symmetric;
using System.Runtime.InteropServices;
using Xunit;
using static EasDotnetSdk.Asymmetric.RSAWrapper;
using static EasDotnetSdk.Symmetric.AESWrapper;

namespace EasDotnetSdk.Tests
{
    public class AESRSAHybridEncryptionTests
    {
        private readonly AESWrapper _aesWrapper;
        private readonly RSAWrapper _rsaWrapper;
        private readonly OperatingSystemDeterminator _operatingSystem;


        public AESRSAHybridEncryptionTests()
        {
            this._aesWrapper = new AESWrapper();
            this._rsaWrapper = new RSAWrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void AESRSAHybridEncrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToEncrypt = "DataToEncrypt";
                string nonce = "TestingNonce";
                RsaKeyPairResult keyPair = this._rsaWrapper.GetKeyPair(2048);
                AesEncryptResult encryptedResult = this._aesWrapper.Aes256Encrypt(nonce, dataToEncrypt);
                string encryptedAesKey = this._rsaWrapper.RsaEncrypt(keyPair.PublicKey, encryptedResult.Key);
                Assert.NotEqual(encryptedResult.Key, encryptedAesKey);
                Assert.NotEqual(dataToEncrypt, encryptedResult.CipherText);
            }
        }

        [Fact]
        public void AESRSAHybridDecrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
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
}