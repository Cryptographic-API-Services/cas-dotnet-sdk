using EasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;
using static EasDotnetSdk.AESWrapper;
using static EasDotnetSdk.RSAWrapper;

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
                RustRsaKeyPair keyPair = this._rsaWrapper.GetKeyPair(2048);
                AesEncrypt encryptedData = this._aesWrapper.EncryptPerformant(nonce, dataToEncrypt);
                string ciphertext = Marshal.PtrToStringAnsi(encryptedData.ciphertext);
                string aesKey = Marshal.PtrToStringAnsi(encryptedData.key);
                string publicKey = Marshal.PtrToStringAnsi(keyPair.pub_key);
                IntPtr encryptedAesKeyPtr = this._rsaWrapper.RsaEncrypt(publicKey, aesKey);
                string encryptedAesKey = Marshal.PtrToStringAnsi(encryptedAesKeyPtr);

                AESWrapper.free_cstring(encryptedData.ciphertext);
                AESWrapper.free_cstring(encryptedData.key);
                RSAWrapper.free_cstring(keyPair.pub_key);
                RSAWrapper.free_cstring(keyPair.priv_key);
                RSAWrapper.free_cstring(encryptedAesKeyPtr);

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
                RustRsaKeyPair keyPair = this._rsaWrapper.GetKeyPair(2048);
                AesEncrypt encryptedData = this._aesWrapper.EncryptPerformant(nonce, dataToEncrypt);
                string ciphertext = Marshal.PtrToStringAnsi(encryptedData.ciphertext);
                string aesKey = Marshal.PtrToStringAnsi(encryptedData.key);
                string publicKey = Marshal.PtrToStringAnsi(keyPair.pub_key);
                string privateKey = Marshal.PtrToStringAnsi(keyPair.priv_key);
                IntPtr encryptedAesKeyPtr = this._rsaWrapper.RsaEncrypt(publicKey, aesKey);
                string encryptedAesKey = Marshal.PtrToStringAnsi(encryptedAesKeyPtr);

                IntPtr decryptedAesKeyPtr = this._rsaWrapper.RsaDecrypt(privateKey, encryptedAesKey);
                string decryptedAesKey = Marshal.PtrToStringAnsi(decryptedAesKeyPtr);
                IntPtr decryptedDataPtr = this._aesWrapper.DecryptPerformant(nonce, decryptedAesKey, ciphertext);
                string decryptedData = Marshal.PtrToStringAnsi(decryptedDataPtr);

                RSAWrapper.free_cstring(keyPair.pub_key);
                RSAWrapper.free_cstring(keyPair.priv_key);
                AESWrapper.free_cstring(encryptedData.ciphertext);
                AESWrapper.free_cstring(encryptedData.key);
                AESWrapper.free_cstring(encryptedAesKeyPtr);
                AESWrapper.free_cstring(decryptedDataPtr);


                Assert.Equal(decryptedData, dataToEncrypt);
            }
        }
    }
}