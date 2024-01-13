using CasDotnetSdk.DigitalSignature;
using CasDotnetSdk.DigitalSignature.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class DigitalSignatureTests
    {
        private readonly DigitalSignatureWrapper _digitalSignatureWrapper;

        public DigitalSignatureTests()
        {
            this._digitalSignatureWrapper = new DigitalSignatureWrapper();
        }

        [Fact]
        public void SHA512RSA4096DigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            SHARSADigitalSignatureResult signature = this._digitalSignatureWrapper.SHA512RSADigitalSignature(4096, dataToSign);
            Assert.NotNull(signature.PublicKey);
            Assert.NotNull(signature.PrivateKey);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void SHA512RSA2048DigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            SHARSADigitalSignatureResult signature = this._digitalSignatureWrapper.SHA512RSADigitalSignature(2048, dataToSign);
            bool result = this._digitalSignatureWrapper.SHA512RSADigitalSignatureVerify(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA512ED25519DigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            SHAED25519DalekDigitialSignatureResult result = this._digitalSignatureWrapper.SHA512ED25519DigitalSignature(dataToSign);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.Signature);
        }

        [Fact]
        public void SHA512ED25519DigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            SHAED25519DalekDigitialSignatureResult result = this._digitalSignatureWrapper.SHA512ED25519DigitalSignature(dataToSign);
            bool result2 = this._digitalSignatureWrapper.SHA512ED25519DigitalSignatureVerify(result.PublicKey, dataToSign, result.Signature);
            Assert.True(result2);
        }
    }
}
