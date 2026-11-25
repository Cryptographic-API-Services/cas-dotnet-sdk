using CasDotnetSdk.Symmetric;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests
{
    public class ChaCha20Poly1305WrapperTests
    {
        private readonly ChaCha20Poly1305Wrapper _wrapper;

        public ChaCha20Poly1305WrapperTests()
        {
            this._wrapper = new ChaCha20Poly1305Wrapper();
        }

        [Fact]
        public void KeyIs32Bytes()
        {
            Assert.Equal(32, this._wrapper.ChaCha20Poly1305Key().Length);
        }

        [Fact]
        public void EncryptDecryptRoundTrip()
        {
            byte[] key = this._wrapper.ChaCha20Poly1305Key();
            byte[] nonce = this._wrapper.ChaCha20Poly1305Nonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("ChaCha20-Poly1305 round trip");
            byte[] ciphertext = this._wrapper.ChaCha20Poly1305Encrypt(nonce, key, plaintext);
            Assert.Equal(plaintext, this._wrapper.ChaCha20Poly1305Decrypt(nonce, key, ciphertext));
        }

        // RFC 8439 section 2.8.2: the AEAD_CHACHA20_POLY1305 test vector.
        private static readonly byte[] RfcKey = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        private static readonly byte[] RfcNonce = Convert.FromHexString("070000004041424344454647");
        private static readonly byte[] RfcAad = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
        private static readonly byte[] RfcPlaintext = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        private static readonly byte[] RfcCiphertextAndTag = Convert.FromHexString(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b" +
            "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116" +
            "1ae10b594f09e26a7e902ecbd0600691");

        [Fact]
        public void EncryptMatchesRfc8439Vector()
        {
            Assert.Equal(RfcCiphertextAndTag, this._wrapper.ChaCha20Poly1305Encrypt(RfcNonce, RfcKey, RfcPlaintext, RfcAad));
        }

        [Fact]
        public void DecryptMatchesRfc8439Vector()
        {
            Assert.Equal(RfcPlaintext, this._wrapper.ChaCha20Poly1305Decrypt(RfcNonce, RfcKey, RfcCiphertextAndTag, RfcAad));
        }

        [Fact]
        public void OpenAcceptsRfc8439VectorAsSealedMessage()
        {
            byte[] sealedMessage = RfcNonce.Concat(RfcCiphertextAndTag).ToArray();
            Assert.Equal(RfcPlaintext, this._wrapper.ChaCha20Poly1305Open(RfcKey, sealedMessage, RfcAad));
        }
    }
}
