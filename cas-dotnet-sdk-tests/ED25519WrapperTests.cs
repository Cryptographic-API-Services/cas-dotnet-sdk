using System.Text;
using CasDotnetSdk.Signatures;
using CasDotnetSdk.Signatures.Types;
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
            byte[] keyPair = this._wrapper.GetKeyPairBytes();
            Assert.NotNull(keyPair);
            Assert.NotEmpty(keyPair);
        }

        [Fact]
        public void GetKeyPairBytesThreadpool()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytesThreadpool();
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
        public void SignDataByesThreadpool()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytes();
            byte[] dataToSign = Encoding.UTF8.GetBytes("SignThisDataWithEd25519Dalek");
            Ed25519ByteSignatureResult result = this._wrapper.SignBytesThreadpool(keyPair, dataToSign);
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
        public void VerifyBytesThreadpool()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytesThreadpool();
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsGarbageDataThatShouldBeIncreased");
            Ed25519ByteSignatureResult signatureResult = this._wrapper.SignBytesThreadpool(keyPair, dataToSign);
            bool isValid = this._wrapper.VerifyBytesThreadpool(keyPair, signatureResult.Signature, dataToSign);
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

        [Fact]
        public void VerifyWithPublicKeyBytesThreadpool()
        {
            byte[] keyPair = this._wrapper.GetKeyPairBytesThreadpool();
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsBadDataToVerifyWithEd25519-Dalek");
            Ed25519ByteSignatureResult result = this._wrapper.SignBytesThreadpool(keyPair, dataToSign);
            bool isValid = this._wrapper.VerifyWithPublicKeyBytesThreadpool(result.PublicKey, result.Signature, dataToSign);
        }
    }
}