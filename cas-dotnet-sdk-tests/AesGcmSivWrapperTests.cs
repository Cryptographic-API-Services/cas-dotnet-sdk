using CasDotnetSdk.Symmetric;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests
{
    public class AesGcmSivWrapperTests
    {
        private readonly AesGcmSivWrapper _wrapper;

        public AesGcmSivWrapperTests()
        {
            this._wrapper = new AesGcmSivWrapper();
        }

        [Fact]
        public void KeysHaveExpectedLength()
        {
            Assert.Equal(16, this._wrapper.Aes128GcmSivKey().Length);
            Assert.Equal(32, this._wrapper.Aes256GcmSivKey().Length);
        }

        [Fact]
        public void Aes128EncryptDecryptRoundTrip()
        {
            byte[] key = this._wrapper.Aes128GcmSivKey();
            byte[] nonce = this._wrapper.GenerateAesGcmSivNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-128-GCM-SIV round trip");
            byte[] ciphertext = this._wrapper.Aes128GcmSivEncrypt(nonce, key, plaintext);
            Assert.Equal(plaintext, this._wrapper.Aes128GcmSivDecrypt(nonce, key, ciphertext));
        }

        [Fact]
        public void Aes256EncryptDecryptRoundTrip()
        {
            byte[] key = this._wrapper.Aes256GcmSivKey();
            byte[] nonce = this._wrapper.GenerateAesGcmSivNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-256-GCM-SIV round trip");
            byte[] ciphertext = this._wrapper.Aes256GcmSivEncrypt(nonce, key, plaintext);
            Assert.Equal(plaintext, this._wrapper.Aes256GcmSivDecrypt(nonce, key, ciphertext));
        }

        [Fact]
        public void NonceReuseOnlyRevealsEqualPlaintexts()
        {
            // With a repeated nonce, equal messages give equal ciphertexts, and different
            // messages still decrypt and stay distinct: the property GCM-SIV promises.
            byte[] key = this._wrapper.Aes256GcmSivKey();
            byte[] nonce = this._wrapper.GenerateAesGcmSivNonce();
            byte[] first = this._wrapper.Aes256GcmSivEncrypt(nonce, key, Encoding.UTF8.GetBytes("message one"));
            byte[] again = this._wrapper.Aes256GcmSivEncrypt(nonce, key, Encoding.UTF8.GetBytes("message one"));
            byte[] other = this._wrapper.Aes256GcmSivEncrypt(nonce, key, Encoding.UTF8.GetBytes("message two"));

            Assert.Equal(first, again);
            Assert.NotEqual(first, other);
        }

        // RFC 8452 appendix C: the nonce is 03 followed by eleven zero bytes.
        private static readonly byte[] RfcNonce = Convert.FromHexString("030000000000000000000000");

        public static IEnumerable<object[]> Rfc8452Aes128Vectors()
        {
            string key = "01000000000000000000000000000000";
            // C.1, empty plaintext and no AAD.
            yield return new object[] { key, "", "", "dc20e2d83f25705bb49e439eca56de25" };
            // C.1, 8-byte plaintext with no AAD.
            yield return new object[] { key, "", "0100000000000000", "b5d839330ac7b786578782fff6013b815b287c22493a364c" };
            // C.1, 8-byte plaintext with 1-byte AAD.
            yield return new object[] { key, "01", "0200000000000000", "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508" };
        }

        public static IEnumerable<object[]> Rfc8452Aes256Vectors()
        {
            string key = "0100000000000000000000000000000000000000000000000000000000000000";
            // C.2, empty plaintext and no AAD.
            yield return new object[] { key, "", "", "07f5f4169bbf55a8400cd47ea6fd400f" };
            // C.2, 8-byte plaintext with 1-byte AAD.
            yield return new object[] { key, "01", "0200000000000000", "1de22967237a813291213f267e3b452f02d01ae33e4ec854" };
        }

        [Theory]
        [MemberData(nameof(Rfc8452Aes128Vectors))]
        public void Aes128MatchesRfc8452Vectors(string keyHex, string aadHex, string plaintextHex, string expectedHex)
        {
            byte[] key = Convert.FromHexString(keyHex);
            byte[] aad = Convert.FromHexString(aadHex);
            byte[] plaintext = Convert.FromHexString(plaintextHex);
            byte[] expected = Convert.FromHexString(expectedHex);

            Assert.Equal(expected, this._wrapper.Aes128GcmSivEncrypt(RfcNonce, key, plaintext, aad));
            Assert.Equal(plaintext, this._wrapper.Aes128GcmSivDecrypt(RfcNonce, key, expected, aad));
            Assert.Equal(plaintext, this._wrapper.Aes128GcmSivOpen(key, RfcNonce.Concat(expected).ToArray(), aad));
            if (aad.Length == 0)
            {
                Assert.Equal(expected, this._wrapper.Aes128GcmSivEncrypt(RfcNonce, key, plaintext));
            }
        }

        [Theory]
        [MemberData(nameof(Rfc8452Aes256Vectors))]
        public void Aes256MatchesRfc8452Vectors(string keyHex, string aadHex, string plaintextHex, string expectedHex)
        {
            byte[] key = Convert.FromHexString(keyHex);
            byte[] aad = Convert.FromHexString(aadHex);
            byte[] plaintext = Convert.FromHexString(plaintextHex);
            byte[] expected = Convert.FromHexString(expectedHex);

            Assert.Equal(expected, this._wrapper.Aes256GcmSivEncrypt(RfcNonce, key, plaintext, aad));
            Assert.Equal(plaintext, this._wrapper.Aes256GcmSivDecrypt(RfcNonce, key, expected, aad));
            Assert.Equal(plaintext, this._wrapper.Aes256GcmSivOpen(key, RfcNonce.Concat(expected).ToArray(), aad));
            if (aad.Length == 0)
            {
                Assert.Equal(expected, this._wrapper.Aes256GcmSivEncrypt(RfcNonce, key, plaintext));
            }
        }
    }
}
