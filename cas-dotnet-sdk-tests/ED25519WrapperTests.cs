using CasDotnetSdk.Signatures;
using System.Text;
using Xunit;
using static CasDotnetSdk.Signatures.ED25519Wrapper;

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
            byte[] keyPair = this._wrapper.GetKeyPairBytes();
            Assert.NotNull(keyPair);
            Assert.NotEmpty(keyPair);
        }

        [Fact]
        public void SignDataByes()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytes();
            byte[] dataToSign = Encoding.UTF8.GetBytes("SignThisDataWithEd25519Dalek");
            Ed25519ByteSignatureResult result = this._wrapper.SignBytes(keyPair, dataToSign);
            Assert.NotNull(result.Signature);
            Assert.NotNull(result.PublicKey);
            Assert.NotEmpty(result.Signature);
            Assert.NotEmpty(result.PublicKey);
        }

        [Fact]
        public void VerifyBytes()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytes();
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsGarbageDataThatShouldBeIncreased");
            Ed25519ByteSignatureResult signatureResult = this._wrapper.SignBytes(keyPair, dataToSign);
            bool isValid = this._wrapper.VerifyBytes(keyPair, signatureResult.Signature, dataToSign);
            Assert.True(isValid);
        }

        [Fact]
        public void VerifyWithPublicKeyBytes()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytes();
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsBadDataToVerifyWithEd25519-Dalek");
            Ed25519ByteSignatureResult result = this._wrapper.SignBytes(keyPair, dataToSign);
            bool isValid = this._wrapper.VerifyWithPublicKeyBytes(result.PublicKey, result.Signature, dataToSign);
        }
    }
}