using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.Symmetric;
using CasDotnetSdk.Symmetric.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class AESWrapperTests
    {
        private readonly AESWrapper _aESWrapper;
        private readonly X25519Wrapper _x25519Wrapper;

        public AESWrapperTests()
        {
            this._aESWrapper = new AESWrapper();
            this._x25519Wrapper = new X25519Wrapper();
        }

        [Fact]
        public void Aes128BytesEncrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes128Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonceKey, key, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }


        [Fact]
        public void AesNonce()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            Assert.True(nonceKey.Length == 12);
        }

        [Fact]
        public void Aes128Key()
        {
            byte[] key = this._aESWrapper.Aes128Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Aes128BytesDecrypt()
        {

            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes128Key();
            byte[] dataToEncrypt = Encoding.ASCII.GetBytes("Thisisthedatathatne1233123123123123123edstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonceKey, key, dataToEncrypt);
            byte[] decrypted = this._aESWrapper.Aes128Decrypt(nonceKey, key, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
        }


        [Fact]
        public void Aes256Key()
        {
            byte[] key = this._aESWrapper.Aes256Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanKeyAndNonce()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            Aes256KeyAndNonceX25519DiffieHellman aliceAesKeyAndNonce = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            Aes256KeyAndNonceX25519DiffieHellman bobAesKeyAndNonce = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.True(aliceAesKeyAndNonce.AesNonce.SequenceEqual(bobAesKeyAndNonce.AesNonce));
            Assert.Equal(aliceAesKeyAndNonce.AesKey, bobAesKeyAndNonce.AesKey);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanKeyAndNonce()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            Aes256KeyAndNonceX25519DiffieHellman aliceAesKeyAndNonce = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            Aes256KeyAndNonceX25519DiffieHellman bobAesKeyAndNonce = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.True(aliceAesKeyAndNonce.AesNonce.SequenceEqual(bobAesKeyAndNonce.AesNonce));
            Assert.Equal(aliceAesKeyAndNonce.AesKey, bobAesKeyAndNonce.AesKey);
        }

        [Fact]
        public void Aes256BytesEncrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes256Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonceKey, key, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes256BytesDecrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes256Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonceKey, key, dataToEncrypt);
            byte[] decrypted = this._aESWrapper.Aes256Decrypt(nonceKey, key, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            Aes256KeyAndNonceX25519DiffieHellman aliceAesKeyAndNonce = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            Aes256KeyAndNonceX25519DiffieHellman bobAesKeyAndNonce = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);


            Assert.True(aliceAesKeyAndNonce.AesNonce.SequenceEqual(bobAesKeyAndNonce.AesNonce));
            Assert.Equal(aliceAesKeyAndNonce.AesKey, bobAesKeyAndNonce.AesKey);

            byte[] toEncrypt = Encoding.UTF8.GetBytes("EncryptThisText");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(aliceAesKeyAndNonce.AesNonce, aliceAesKeyAndNonce.AesKey, toEncrypt);
            byte[] plaintext = this._aESWrapper.Aes256Decrypt(bobAesKeyAndNonce.AesNonce, bobAesKeyAndNonce.AesKey, encrypted);
            Assert.Equal(toEncrypt, plaintext);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            Aes256KeyAndNonceX25519DiffieHellman aliceAesKeyAndNonce = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            Aes256KeyAndNonceX25519DiffieHellman bobAesKeyAndNonce = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.True(aliceAesKeyAndNonce.AesNonce.SequenceEqual(bobAesKeyAndNonce.AesNonce));
            Assert.Equal(aliceAesKeyAndNonce.AesKey, bobAesKeyAndNonce.AesKey);

            byte[] toEncrypt = Encoding.UTF8.GetBytes("EncryptThisText");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(aliceAesKeyAndNonce.AesNonce, aliceAesKeyAndNonce.AesKey, toEncrypt);
            byte[] plaintext = this._aESWrapper.Aes128Decrypt(bobAesKeyAndNonce.AesNonce, bobAesKeyAndNonce.AesKey, encrypted);
            Assert.Equal(toEncrypt, plaintext);
        }
    }
}
