using System.Runtime.InteropServices;
using System.Text;
using Xunit;
using static EasDotnetSdk.AESWrapper;

namespace EasDotnetSdk.Tests
{
    public class AESWrapperTests
    {
        private readonly AESWrapper _aESWrapper;

        public AESWrapperTests()
        {
            this._aESWrapper = new AESWrapper();
        }

        [Fact]
        public void Aes128Encrypt()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string dataToEncrypt = "TestDataToIUSADKJALSD";
            AesEncrypt result = this._aESWrapper.Aes128Encrypt(nonceKey, dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(result.ciphertext);
            AESWrapper.free_cstring(result.key);
            AESWrapper.free_cstring(result.ciphertext);
            Assert.NotEqual(encrypted, dataToEncrypt);
        }

        [Fact]
        public void Aes128EncryptWithKey()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            IntPtr keyPtr = this._aESWrapper.Aes128Key();
            string key = Marshal.PtrToStringAnsi(keyPtr);
            AESWrapper.free_cstring(keyPtr);
            string dataToEncrypt = "EncryptThisString";
            IntPtr encryptedPtr = this._aESWrapper.EncryptAES128WithKey(nonceKey, key, dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            AESWrapper.free_cstring(encryptedPtr);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes128Key()
        {
            IntPtr keyPtr = this._aESWrapper.Aes128Key();
            string key = Marshal.PtrToStringAnsi(keyPtr);
            AESWrapper.free_cstring(keyPtr);
            Assert.True(!string.IsNullOrEmpty(key));
        }

        [Fact]
        public void Aes128Decrypt()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            IntPtr keyPtr = this._aESWrapper.Aes128Key();
            string key = Marshal.PtrToStringAnsi(keyPtr);
            AESWrapper.free_cstring(keyPtr);
            string dataToEncrypt = "EncryptThisString";
            IntPtr encryptedPtr = this._aESWrapper.EncryptAES128WithKey(nonceKey, key, dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            AESWrapper.free_cstring(encryptedPtr);
            IntPtr decryptedPtr = this._aESWrapper.DecryptAES128WithKey(nonceKey, key, encrypted);
            string decrypted = Marshal.PtrToStringAnsi(decryptedPtr);
            AESWrapper.free_cstring(decryptedPtr);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public void Aes256Key()
        {
            IntPtr keyPtr = this._aESWrapper.Aes256Key();
            string key = Marshal.PtrToStringAnsi(keyPtr);
            AESWrapper.free_cstring(keyPtr);
            Assert.True(!string.IsNullOrEmpty(key));
        }

        [Fact]
        public void EncryptPerformant()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string toEncrypt = "Text to encrypt";
            AesEncrypt encrypted = this._aESWrapper.EncryptPerformant(nonceKey, toEncrypt);
            string cipherText = Convert.ToBase64String(Encoding.ASCII.GetBytes(Marshal.PtrToStringAnsi(encrypted.ciphertext)));
            AESWrapper.free_cstring(encrypted.ciphertext);
            AESWrapper.free_cstring(encrypted.key);
            Assert.NotEqual(toEncrypt, cipherText);
        }

        [Fact]
        public void DecryptPerformant()
        {
            string nonceKey = this._aESWrapper.GenerateAESNonce();
            string toEncrypt = "Text to encrypt";
            AesEncrypt encrypted = this._aESWrapper.EncryptPerformant(nonceKey, toEncrypt);
            string cipherText = Marshal.PtrToStringAnsi(encrypted.ciphertext);
            string key = Marshal.PtrToStringAnsi(encrypted.key);
            AESWrapper.free_cstring(encrypted.ciphertext);
            AESWrapper.free_cstring(encrypted.key);
            IntPtr decryptedPtr = this._aESWrapper.DecryptPerformant(nonceKey, key, cipherText);
            string decrypted = Marshal.PtrToStringAnsi(decryptedPtr);
            AESWrapper.free_cstring(decryptedPtr);
            Assert.Equal(toEncrypt, decrypted);
        }
    }
}
