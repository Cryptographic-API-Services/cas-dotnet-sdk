using CasDotnetSdk.Helpers;
using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.Symmetric;
using CasDotnetSdkTests.Nist;
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
        public void Aes256Key()
        {
            byte[] key = this._aESWrapper.Aes256Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanKey()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

            Assert.Equal(aliceAesKey, bobAesKey);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanKey()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

            Assert.Equal(aliceAesKey, bobAesKey);
        }

        [Fact]
        public void X25519DerivedKeysAreBoundToCipherAndKeySize()
        {
            X25519SecretPublicKey alice = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bob = this._x25519Wrapper.GenerateSecretAndPublicKey();
            byte[] sharedSecret = this._x25519Wrapper.GenerateSharedSecret(alice.SecretKey, bob.PublicKey).SharedSecret;

            byte[] aes256Key = this._aESWrapper.Aes256KeyFromX25519SharedSecret(sharedSecret, alice.PublicKey, bob.PublicKey);
            byte[] aes128Key = this._aESWrapper.Aes128KeyFromX25519SharedSecret(sharedSecret, alice.PublicKey, bob.PublicKey);

            Assert.Equal(32, aes256Key.Length);
            Assert.Equal(16, aes128Key.Length);
            Assert.NotEqual(sharedSecret, aes256Key);
            Assert.NotEqual(aes256Key[..16], aes128Key);
        }

        [Fact]
        public void X25519DerivedKeyRejectsAllZeroSharedSecret()
        {
            X25519SecretPublicKey alice = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bob = this._x25519Wrapper.GenerateSecretAndPublicKey();

            CasException ex = Assert.Throws<CasException>(() => this._aESWrapper.Aes256KeyFromX25519SharedSecret(new byte[32], alice.PublicKey, bob.PublicKey));
            Assert.Equal(CasErrorCode.InvalidKey, ex.ErrorCode);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

            Assert.Equal(aliceAesKey, bobAesKey);
            byte[] nonce = this._aESWrapper.GenerateAESNonce();
            byte[] toEncrypt = Encoding.UTF8.GetBytes("EncryptThisText");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonce, aliceAesKey, toEncrypt);
            byte[] plaintext = this._aESWrapper.Aes256Decrypt(nonce, bobAesKey, encrypted);
            Assert.Equal(toEncrypt, plaintext);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

            Assert.Equal(aliceAesKey, bobAesKey);
            byte[] nonce = this._aESWrapper.GenerateAESNonce();
            byte[] toEncrypt = Encoding.UTF8.GetBytes("EncryptThisText");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonce, aliceAesKey, toEncrypt);
            byte[] plaintext = this._aESWrapper.Aes128Decrypt(nonce, bobAesKey, encrypted);
            Assert.Equal(toEncrypt, plaintext);
        }

        [Theory]
        [MemberData(nameof(AES128NistVectors))]
        public void Aes128MatchesNistEncryptVectors(byte[] nonce, byte[] key, byte[] plaintext, byte[] expectedCiphertext)
        {
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonce, key, plaintext);

            Assert.Equal(expectedCiphertext, encrypted.Take(expectedCiphertext.Length).ToArray());
        }

        [Theory]
        [MemberData(nameof(AES256NistVectors))]
        public void Aes256MatchesNistEncryptVectors(byte[] nonce, byte[] key, byte[] plaintext, byte[] expectedCiphertext)
        {
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonce, key, plaintext);

            Assert.Equal(expectedCiphertext, encrypted.Take(expectedCiphertext.Length).ToArray());
        }

        [Theory]
        [MemberData(nameof(AES128NistAadDecryptVectors))]
        public void Aes128WithAadMatchesNistDecryptVectors(byte[] nonce, byte[] key, byte[] ciphertextAndTag, byte[] aad, byte[] expectedPlaintext, bool expectFailure)
        {
            AssertNistAadDecrypt(this._aESWrapper.Aes128Decrypt, this._aESWrapper.Aes128Encrypt, nonce, key, ciphertextAndTag, aad, expectedPlaintext, expectFailure);
        }

        [Theory]
        [MemberData(nameof(AES256NistAadDecryptVectors))]
        public void Aes256WithAadMatchesNistDecryptVectors(byte[] nonce, byte[] key, byte[] ciphertextAndTag, byte[] aad, byte[] expectedPlaintext, bool expectFailure)
        {
            AssertNistAadDecrypt(this._aESWrapper.Aes256Decrypt, this._aESWrapper.Aes256Encrypt, nonce, key, ciphertextAndTag, aad, expectedPlaintext, expectFailure);
        }

        private static void AssertNistAadDecrypt(
            Func<byte[], byte[], byte[], byte[]?, byte[]> decrypt,
            Func<byte[], byte[], byte[], byte[]?, byte[]> encrypt,
            byte[] nonce, byte[] key, byte[] ciphertextAndTag, byte[] aad, byte[] expectedPlaintext, bool expectFailure)
        {
            if (expectFailure)
            {
                CasException ex = Assert.Throws<CasException>(() => decrypt(nonce, key, ciphertextAndTag, aad));
                Assert.Equal(CasErrorCode.DecryptionFailed, ex.ErrorCode);
                return;
            }

            Assert.Equal(expectedPlaintext, decrypt(nonce, key, ciphertextAndTag, aad));
            Assert.Equal(ciphertextAndTag, encrypt(nonce, key, expectedPlaintext, aad));
        }

        public static IEnumerable<object[]> AES128NistAadDecryptVectors()
        {
            return GcmAadDecryptVectors("gcmDecrypt128.rsp").Vectors;
        }

        public static IEnumerable<object[]> AES256NistAadDecryptVectors()
        {
            return GcmAadDecryptVectors("gcmDecrypt256.rsp").Vectors;
        }

        public static IEnumerable<object[]> AES128NistVectors()
        {
            return GcmEncryptVectors("gcmDecrypt128.rsp").Vectors;
        }

        public static IEnumerable<object[]> AES256NistVectors()
        {
            return GcmEncryptVectors("gcmDecrypt256.rsp").Vectors;
        }

        [Theory]
        [InlineData("gcmDecrypt128.rsp", 375, 7500, 255, 7620)]
        [InlineData("gcmDecrypt256.rsp", 375, 7500, 268, 7607)]
        public void NistVectorCountsArePinned(string fileName, int aadRun, int aadSkipped, int encryptRun, int encryptSkipped)
        {
            var aad = GcmAadDecryptVectors(fileName);
            NistVectors.AssertCounts($"{fileName} (AAD decrypt)", aadRun, aadSkipped, aad.Vectors.Count, aad.Skipped);
            var encrypt = GcmEncryptVectors(fileName);
            NistVectors.AssertCounts($"{fileName} (encrypt, no AAD)", encryptRun, encryptSkipped, encrypt.Vectors.Count, encrypt.Skipped);
        }

        // The 96-bit IV, 128-bit tag cases (the only shape the SDK's AES-GCM takes) for every AAD
        // length, including the FAIL cases, as (IV, key, CT || tag, AAD, PT, FAIL).
        private static (List<object[]> Vectors, int Skipped) GcmAadDecryptVectors(string fileName)
        {
            var vectors = new List<object[]>();
            int skipped = 0;
            foreach (RspRecord record in RspFile.Read(fileName))
            {
                if (record["IVlen"] != "96" || record["Taglen"] != "128")
                {
                    skipped++;
                    continue;
                }
                vectors.Add(new object[]
                {
                    record.Bytes("IV"),
                    record.Bytes("Key"),
                    record.Bytes("CT").Concat(record.Bytes("Tag")).ToArray(),
                    record.Bytes("AAD"),
                    record.Failed ? Array.Empty<byte>() : record.Bytes("PT"),
                    record.Failed
                });
            }
            return (vectors, skipped);
        }

        // The passing 96-bit IV cases without AAD, as (IV, key, PT, CT): the 3-argument
        // Aes*Encrypt has no AAD, and the test compares only the ciphertext, so any tag length works.
        private static (List<object[]> Vectors, int Skipped) GcmEncryptVectors(string fileName)
        {
            var vectors = new List<object[]>();
            int skipped = 0;
            foreach (RspRecord record in RspFile.Read(fileName))
            {
                if (record.Failed || record["IVlen"] != "96" || record["AADlen"] != "0")
                {
                    skipped++;
                    continue;
                }
                vectors.Add(new object[] { record.Bytes("IV"), record.Bytes("Key"), record.Bytes("PT"), record.Bytes("CT") });
            }
            return (vectors, skipped);
        }
    }
}
