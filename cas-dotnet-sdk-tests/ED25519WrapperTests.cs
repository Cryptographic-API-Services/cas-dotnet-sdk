using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class ED25519WrapperTests
    {
        private readonly ED25519Wrapper _wrapper;
        public ED25519WrapperTests()
        {
            this._wrapper = new ED25519Wrapper();
        }

        [Fact]
        public void GetKeyPairBytes()
        {
            var keyPair = this._wrapper.GetKeyPair();
            Assert.NotNull(keyPair.SigningKey);
            Assert.NotEmpty(keyPair.SigningKey);
            Assert.NotNull(keyPair.VerifyingKey);
            Assert.NotEmpty(keyPair.VerifyingKey);
        }

        [Fact]
        public void SignDataByes()
        {
            var keyPair = this._wrapper.GetKeyPair();
            byte[] dataToSign = Encoding.UTF8.GetBytes("SignThisDataWithEd25519Dalek");
            Ed25519ByteSignatureResult result = this._wrapper.SignBytes(keyPair.SigningKey, dataToSign);
            Assert.NotNull(result.Signature);
            Assert.NotNull(result.PublicKey);
            Assert.NotEmpty(result.Signature);
            Assert.NotEmpty(result.PublicKey);
        }

        [Fact]
        public void VerifyBytes()
        {
            var keyPair = this._wrapper.GetKeyPair();
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsGarbageDataThatShouldBeIncreased");
            Ed25519ByteSignatureResult signatureResult = this._wrapper.SignBytes(keyPair.SigningKey, dataToSign);
#pragma warning disable CS0618 // VerifyBytes is obsolete; this test covers it until it is removed.
            bool isValid = this._wrapper.VerifyBytes(keyPair.SigningKey, signatureResult.Signature, dataToSign);
#pragma warning restore CS0618
            Assert.True(isValid);
        }

        [Fact]
        public void VerifyWithPublicKeyBytes()
        {
            var keyPair = this._wrapper.GetKeyPair();
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsBadDataToVerifyWithEd25519-Dalek");
            Ed25519ByteSignatureResult result = this._wrapper.SignBytes(keyPair.SigningKey, dataToSign);
            bool isValid = this._wrapper.VerifyWithPublicKeyBytes(result.PublicKey, result.Signature, dataToSign);
            Assert.True(isValid);
        }

        [Fact]
        public void PublicKeyFromSigningMatchesGeneratedVerifyingKey()
        {
            var keyPair = this._wrapper.GetKeyPair();
            Ed25519ByteSignatureResult result = this._wrapper.SignBytes(keyPair.SigningKey, Encoding.UTF8.GetBytes("message"));
            Assert.Equal(keyPair.VerifyingKey, result.PublicKey);
            Assert.Equal(64, result.Signature.Length);
        }

        [Fact]
        public void BothVerifyMethodsRejectTamperedInput()
        {
            var keyPair = this._wrapper.GetKeyPair();
            byte[] data = Encoding.UTF8.GetBytes("Original message");
            byte[] signature = this._wrapper.SignBytes(keyPair.SigningKey, data).Signature;
            byte[] tamperedSignature = (byte[])signature.Clone();
            tamperedSignature[10] ^= 0x01;
            byte[] tamperedData = Encoding.UTF8.GetBytes("Tampered message");

            Assert.False(this._wrapper.VerifyWithPublicKeyBytes(keyPair.VerifyingKey, tamperedSignature, data));
            Assert.False(this._wrapper.VerifyWithPublicKeyBytes(keyPair.VerifyingKey, signature, tamperedData));
#pragma warning disable CS0618 // VerifyBytes is obsolete; this test checks it agrees with VerifyWithPublicKeyBytes.
            Assert.False(this._wrapper.VerifyBytes(keyPair.SigningKey, tamperedSignature, data));
            Assert.False(this._wrapper.VerifyBytes(keyPair.SigningKey, signature, tamperedData));
#pragma warning restore CS0618
        }

        [Fact]
        public void BothVerifyMethodsRejectSmallOrderR()
        {
            // #220: build a signature whose R is the identity point (a small-order point, canonically
            // encoded as 01 00..00) with s = k*a mod L, where k = SHA-512(R || A || M) mod L. Then
            // [s]B - [k]A is the identity, which equals R, so a non-strict (cofactorless) verifier
            // such as ed25519-dalek's plain verify() accepts it. verify_strict rejects any signature
            // with a small-order R, and both SDK methods must agree.
            var keyPair = this._wrapper.GetKeyPair();
            byte[] message = Encoding.UTF8.GetBytes("small-order R");

            byte[] h = SHA512.HashData(keyPair.SigningKey);
            byte[] scalarBytes = h.AsSpan(0, 32).ToArray();
            scalarBytes[0] &= 248;
            scalarBytes[31] &= 127;
            scalarBytes[31] |= 64;
            BigInteger a = new BigInteger(scalarBytes, isUnsigned: true, isBigEndian: false);

            byte[] r = new byte[32];
            r[0] = 1; // the identity point
            byte[] kHash = SHA512.HashData(r.Concat(keyPair.VerifyingKey).Concat(message).ToArray());
            BigInteger order = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
            BigInteger k = new BigInteger(kHash, isUnsigned: true, isBigEndian: false) % order;
            byte[] s = new byte[32];
            ((k * a) % order).TryWriteBytes(s, out _, isUnsigned: true, isBigEndian: false);
            byte[] signature = r.Concat(s).ToArray();

            Assert.False(this._wrapper.VerifyWithPublicKeyBytes(keyPair.VerifyingKey, signature, message));
#pragma warning disable CS0618 // VerifyBytes is obsolete; this test checks it is strict too.
            Assert.False(this._wrapper.VerifyBytes(keyPair.SigningKey, signature, message));
#pragma warning restore CS0618
        }
    }
}