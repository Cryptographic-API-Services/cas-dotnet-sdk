using CasDotnetSdk.Helpers;
using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Hybrid.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests
{
    public class HpkeWrapperTests
    {
        private HpkeWrapper _wrapper { get; set; }

        public HpkeWrapperTests()
        {
            this._wrapper = new HpkeWrapper();
        }

        [Fact]
        public void GenerateKeyPair()
        {
            HpkeKeyPairResult result = this._wrapper.GenerateKeyPair();
            Assert.NotNull(result.PublicKey);
            Assert.NotNull(result.PrivateKey);
            Assert.NotEmpty(result.InfoStr);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.PrivateKey);
            Assert.NotEmpty(result.InfoStr);
        }

        [Fact]
        public void Encrypt()
        {
            HpkeKeyPairResult keyPair = this._wrapper.GenerateKeyPair();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("EncryptThisDataString");
            HpkeEncryptResult result = this._wrapper.Encrypt(dataToEncrypt, keyPair.PublicKey, keyPair.InfoStr);
            Assert.NotNull(result.EncappedKey);
            Assert.NotNull(result.Ciphertext);
            Assert.NotNull(result.Tag);
            Assert.NotEmpty(result.EncappedKey);
            Assert.NotEmpty(result.Ciphertext);
            Assert.NotEmpty(result.Tag);
        }

        [Fact]
        public void Decrypt()
        {
            HpkeKeyPairResult keyPair = this._wrapper.GenerateKeyPair();
            string dataToEncrypt = "EncryptThisDataString";
            byte[] plaintext = Encoding.UTF8.GetBytes(dataToEncrypt);
            HpkeEncryptResult result = this._wrapper.Encrypt(plaintext, keyPair.PublicKey, keyPair.InfoStr);
            byte[] decrypted = this._wrapper.Decrypt(result.Ciphertext, keyPair.PrivateKey, result.EncappedKey, result.Tag, keyPair.InfoStr);
            Assert.Equal(dataToEncrypt, Encoding.UTF8.GetString(decrypted));
        }


        [Fact]
        public void EncryptDecryptWithAad()
        {
            HpkeKeyPairResult keyPair = this._wrapper.GenerateKeyPair();
            byte[] plaintext = Encoding.UTF8.GetBytes("Bound to a record id");
            byte[] aad = Encoding.UTF8.GetBytes("record-42");
            HpkeEncryptResult encrypted = this._wrapper.Encrypt(plaintext, keyPair.PublicKey, keyPair.InfoStr, aad);

            byte[] decrypted = this._wrapper.Decrypt(encrypted.Ciphertext, keyPair.PrivateKey, encrypted.EncappedKey, encrypted.Tag, keyPair.InfoStr, aad);
            Assert.Equal(plaintext, decrypted);

            Assert.Throws<CasException>(() => this._wrapper.Decrypt(encrypted.Ciphertext, keyPair.PrivateKey, encrypted.EncappedKey, encrypted.Tag, keyPair.InfoStr, Encoding.UTF8.GetBytes("record-43")));
            Assert.Throws<CasException>(() => this._wrapper.Decrypt(encrypted.Ciphertext, keyPair.PrivateKey, encrypted.EncappedKey, encrypted.Tag, keyPair.InfoStr));
        }
    }
}
