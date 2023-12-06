using System.Runtime.InteropServices;
using Xunit;
using static EasDotnetSdk.RSAWrapper;

namespace EasDotnetSdk.Tests
{
    public class RSAWrapperTests
    {
        private readonly RSAWrapper _RSAWrapper;
        private readonly RustRsaKeyPair _encryptDecryptKeyPair;

        public RSAWrapperTests()
        {
            this._RSAWrapper = new RSAWrapper();
            this._encryptDecryptKeyPair = this._RSAWrapper.GetKeyPairAsync(4096).GetAwaiter().GetResult();
        }

        [Fact]
        public void CreateKeyPair()
        {
            RustRsaKeyPair keyPair = this._RSAWrapper.GetKeyPair(4096);
            string privateKey = Marshal.PtrToStringAnsi(keyPair.priv_key);
            string publicKey = Marshal.PtrToStringAnsi(keyPair.pub_key);
            RSAWrapper.free_cstring(keyPair.priv_key);
            RSAWrapper.free_cstring(keyPair.pub_key);
            Assert.NotNull(privateKey);
            Assert.NotNull(publicKey);
        }

        [Fact]
        public async Task CreateKeyPairAsync()
        {
            RustRsaKeyPair keyPair = await this._RSAWrapper.GetKeyPairAsync(4096);
            string privateKey = Marshal.PtrToStringAnsi(keyPair.priv_key);
            string publicKey = Marshal.PtrToStringAnsi(keyPair.pub_key);
            RSAWrapper.free_cstring(keyPair.priv_key);
            RSAWrapper.free_cstring(keyPair.pub_key);
            Assert.NotNull(privateKey);
            Assert.NotNull(publicKey);
        }

        [Fact]
        public void RsaEncrypt()
        {
            string dataToEncrypt = "EncryptingStuffIsFun";
            IntPtr encryptedPtr = this._RSAWrapper.RsaEncrypt(Marshal.PtrToStringAnsi(this._encryptDecryptKeyPair.pub_key), dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            RSAWrapper.free_cstring(encryptedPtr);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public async Task RsaEncryptAsync()
        {
            string dataToEncrypt = "EncryptingStuffIsFun";
            IntPtr encryptedPtr = await this._RSAWrapper.RsaEncryptAsync(Marshal.PtrToStringAnsi(this._encryptDecryptKeyPair.pub_key), dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            RSAWrapper.free_cstring(encryptedPtr);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void RsaDecrypt()
        {
            string dataToEncrypt = "EncryptingStuffIsFun";
            IntPtr encryptedPtr = this._RSAWrapper.RsaEncrypt(Marshal.PtrToStringAnsi(this._encryptDecryptKeyPair.pub_key), dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            IntPtr decryptedPtr = this._RSAWrapper.RsaDecrypt(Marshal.PtrToStringAnsi(this._encryptDecryptKeyPair.priv_key), encrypted);
            string decrypted = Marshal.PtrToStringAnsi(decryptedPtr);
            RSAWrapper.free_cstring(encryptedPtr);
            RSAWrapper.free_cstring(decryptedPtr);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public async Task RsaDecryptAsync()
        {
            string dataToEncrypt = "EncryptingStuffIsFun";
            IntPtr encryptedPtr = await this._RSAWrapper.RsaEncryptAsync(Marshal.PtrToStringAnsi(this._encryptDecryptKeyPair.pub_key), dataToEncrypt);
            string encrypted = Marshal.PtrToStringAnsi(encryptedPtr);
            IntPtr decryptedPtr = await this._RSAWrapper.RsaDecryptAsync(Marshal.PtrToStringAnsi(this._encryptDecryptKeyPair.priv_key), encrypted);
            string decrypted = Marshal.PtrToStringAnsi(decryptedPtr);
            RSAWrapper.free_cstring(encryptedPtr);
            RSAWrapper.free_cstring(decryptedPtr);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public async void RsaSign()
        {
            string dataToSign = "Sign This Data For Me";
            RsaSignResult result = this._RSAWrapper.RsaSign(dataToSign, 4096);
            string publicKey = Marshal.PtrToStringAnsi(result.public_key);
            string signature = Marshal.PtrToStringAnsi(result.signature);
            RSAWrapper.free_cstring(result.public_key);
            RSAWrapper.free_cstring(result.signature);
            Assert.NotNull(publicKey);
            Assert.NotNull(signature);
        }

        [Fact]
        public async Task RsaSignAsync()
        {
            string dataToSign = "Data That Needs To Be Signed Via RSA";
            RsaSignResult result = await this._RSAWrapper.RsaSignAsync(dataToSign, 4096);
            string publicKey = Marshal.PtrToStringAnsi(result.public_key);
            string signature = Marshal.PtrToStringAnsi(result.signature);
            RSAWrapper.free_cstring(result.public_key);
            RSAWrapper.free_cstring(result.signature);
            Assert.NotNull(publicKey);
            Assert.NotNull(signature);
        }

        [Fact]
        public async void RsaVerify()
        {
            string dataToSign = "Data That Needs To Be Verified";
            RsaSignResult result = this._RSAWrapper.RsaSign(dataToSign, 4096);
            string publicKey = Marshal.PtrToStringAnsi(result.public_key);
            string signature = Marshal.PtrToStringAnsi(result.signature);
            bool isValid = this._RSAWrapper.RsaVerify(publicKey, dataToSign, signature);
            RSAWrapper.free_cstring(result.public_key);
            RSAWrapper.free_cstring(result.signature);
            Assert.Equal(true, isValid);
        }


        [Fact]
        public async Task RsaVerifyAsync()
        {
            string dataToSign = "Data That Needs To Be Verified";
            RsaSignResult result = await this._RSAWrapper.RsaSignAsync(dataToSign, 4096);
            string publicKey = Marshal.PtrToStringAnsi(result.public_key);
            string signature = Marshal.PtrToStringAnsi(result.signature);
            RSAWrapper.free_cstring(result.public_key);
            RSAWrapper.free_cstring(result.signature);
            bool isValid = await this._RSAWrapper.RsaVerifyAsync(publicKey, dataToSign, signature);
            Assert.Equal(true, isValid);
        }

        [Fact]
        public async void RsaSignWithKey()
        {
            string dataToSign = "This data needs to be signed now";
            RustRsaKeyPair keyPair = this._RSAWrapper.GetKeyPair(2048);
            string privateKey = Marshal.PtrToStringAnsi(keyPair.priv_key);
            IntPtr signaturePtr = this._RSAWrapper.RsaSignWithKey(privateKey, dataToSign);
            string signature = Marshal.PtrToStringAnsi(signaturePtr);
            RSAWrapper.free_cstring(keyPair.priv_key);
            RSAWrapper.free_cstring(keyPair.pub_key);
            RSAWrapper.free_cstring(signaturePtr);
            Assert.NotNull(signature);
            Assert.NotEqual(dataToSign, signature);
        }

        [Fact]
        public async Task RsaSignWithKeyAsync()
        {
            string dataToSign = "This data needs to be signed now";
            RustRsaKeyPair keyPair = await this._RSAWrapper.GetKeyPairAsync(2048);
            string privateKey = Marshal.PtrToStringAnsi(keyPair.priv_key);
            IntPtr signaturePtr = await this._RSAWrapper.RsaSignWithKeyAsync(privateKey, dataToSign);
            string signature = Marshal.PtrToStringAnsi(signaturePtr);
            RSAWrapper.free_cstring(keyPair.priv_key);
            RSAWrapper.free_cstring(keyPair.pub_key);
            RSAWrapper.free_cstring(signaturePtr);
            Assert.NotNull(signature);
            Assert.NotEqual(dataToSign, signature);
        }
    }
}