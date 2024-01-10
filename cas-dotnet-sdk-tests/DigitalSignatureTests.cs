using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.DigitalSignature;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using static CasDotnetSdk.DigitalSignature.DigitalSignatureWrapper;

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
    }
}
