using CasDotnetSdk.DigitalSignature;
using CasDotnetSdk.DigitalSignature.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class DigitalSignatureTests
    {
        public DigitalSignatureTests()
        {
        }

        [Fact]
        public void SHA512RSA4096DigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            IDigitalSignature digitalSignature = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHARSADigitalSignatureResult signature = digitalSignature.CreateRsa(4096, dataToSign);
            Assert.NotNull(signature.PublicKey);
            Assert.NotNull(signature.PrivateKey);
            Assert.NotEmpty(signature.Signature);
        }


        [Fact]
        public void SHA512RSA2048DigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            IDigitalSignature digitalSignature = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHARSADigitalSignatureResult signature = digitalSignature.CreateRsa(2048, dataToSign);
            bool result = digitalSignature.VerifyRsa(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA256RSADigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsa(4096, dataToSign);
            Assert.NotNull(signature.PublicKey);
            Assert.NotNull(signature.PrivateKey);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void SHA256RSADigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsa(4096, dataToSign);
            bool result = wrapper.VerifyRsa(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }


        [Fact]
        public void SHA256RSADigitalSignatureVerifyFail()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsa(4096, dataToSign);
            dataToSign = Encoding.UTF8.GetBytes("NOtTheSameData");
            bool result = wrapper.VerifyRsa(signature.PublicKey, dataToSign, signature.Signature);
            Assert.False(result);
        }
    }
}
