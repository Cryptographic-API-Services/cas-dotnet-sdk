using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;
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
            bool isValid = this._wrapper.VerifyBytes(keyPair.SigningKey, signatureResult.Signature, dataToSign);
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
    }
}