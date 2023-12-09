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
                AesEncrypt encryptedData = this._aesWrapper.EncryptPerformant(nonce, dataToEncrypt);
                string ciphertext = Marshal.PtrToStringAnsi(encryptedData.ciphertext);
                string aesKey = Marshal.PtrToStringAnsi(encryptedData.key);
                string encryptedAesKey = this._rsaWrapper.RsaEncrypt(keyPair.PublicKey, aesKey);

                AESWrapper.free_cstring(encryptedData.ciphertext);
                AESWrapper.free_cstring(encryptedData.key);

                Assert.NotEqual(aesKey, encryptedAesKey);
                Assert.NotEqual(dataToEncrypt, ciphertext);
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
                AesEncrypt encryptedData = this._aesWrapper.EncryptPerformant(nonce, dataToEncrypt);
                string ciphertext = Marshal.PtrToStringAnsi(encryptedData.ciphertext);
                string aesKey = Marshal.PtrToStringAnsi(encryptedData.key);
                string encryptedAesKey = this._rsaWrapper.RsaEncrypt(keyPair.PublicKey, aesKey);

                string decryptedAesKey = this._rsaWrapper.RsaDecrypt(keyPair.PrivateKey, encryptedAesKey);
                IntPtr decryptedDataPtr = this._aesWrapper.DecryptPerformant(nonce, decryptedAesKey, ciphertext);
                string decryptedData = Marshal.PtrToStringAnsi(decryptedDataPtr);

                AESWrapper.free_cstring(encryptedData.ciphertext);
                AESWrapper.free_cstring(encryptedData.key);
                AESWrapper.free_cstring(decryptedDataPtr);


                Assert.Equal(decryptedData, dataToEncrypt);
            }
        }
    }
}