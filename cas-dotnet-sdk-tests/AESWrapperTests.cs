using CasDotnetSdk.Helpers;
using CasDotnetSdk.Symmetric;
using System.Runtime.InteropServices;
using Xunit;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdkTests.Tests
{
    public class AESWrapperTests
    {
        private readonly AESWrapper _aESWrapper;
        private readonly OperatingSystemDeterminator _operatingSystem;

        public AESWrapperTests()
        {
            this._aESWrapper = new AESWrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void Aes128Encrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string nonceKey = this._aESWrapper.GenerateAESNonce();
                string dataToEncrypt = "TestDataToIUSADKJALSD";
                AesEncryptResult result = this._aESWrapper.Aes128Encrypt(nonceKey, dataToEncrypt);
                Assert.NotEqual(result.CipherText, dataToEncrypt);
            }
        }

        [Fact]
        public void Aes128EncryptWithKey()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string nonceKey = this._aESWrapper.GenerateAESNonce();
                string key = this._aESWrapper.Aes128Key();
                string dataToEncrypt = "EncryptThisString";
                string encrypted = this._aESWrapper.EncryptAES128WithKey(nonceKey, key, dataToEncrypt);
                Assert.NotEqual(dataToEncrypt, encrypted);
            }
        }

        [Fact]
        public void Aes128Key()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string key = this._aESWrapper.Aes128Key();
                Assert.True(!string.IsNullOrEmpty(key));
            }
        }

        [Fact]
        public void Aes128Decrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string nonceKey = this._aESWrapper.GenerateAESNonce();
                string key = this._aESWrapper.Aes128Key();
                string dataToEncrypt = "EncryptThisString";
                string encrypted = this._aESWrapper.EncryptAES128WithKey(nonceKey, key, dataToEncrypt);
                string decrypted = this._aESWrapper.DecryptAES128WithKey(nonceKey, key, encrypted);
                Assert.Equal(dataToEncrypt, decrypted);
            }
        }

        [Fact]
        public void Aes256Key()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string key = this._aESWrapper.Aes256Key();
                Assert.True(!string.IsNullOrEmpty(key));
            }
        }

        [Fact]
        public void Aes256Encrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string nonceKey = this._aESWrapper.GenerateAESNonce();
                string toEncrypt = "Text to encrypt";
                AesEncryptResult encrypted = this._aESWrapper.Aes256Encrypt(nonceKey, toEncrypt);
                Assert.NotEqual(toEncrypt, encrypted.CipherText);
            }
        }

        [Fact]
        public void Aes256Decrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string nonceKey = this._aESWrapper.GenerateAESNonce();
                string toEncrypt = "Text to encrypt";
                AesEncryptResult encrypted = this._aESWrapper.Aes256Encrypt(nonceKey, toEncrypt);
                string decrypted = this._aESWrapper.Aes256Decrypt(nonceKey, encrypted.Key, encrypted.CipherText);
                Assert.Equal(toEncrypt, decrypted);
            }
        }
    }
}
