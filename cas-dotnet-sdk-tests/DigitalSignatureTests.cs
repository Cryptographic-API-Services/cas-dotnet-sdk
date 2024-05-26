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
        public void SHA512RSA4096DigitalSignatureThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            IDigitalSignature digitalSignature = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHARSADigitalSignatureResult signature = digitalSignature.CreateRsaThreadpool(4096, dataToSign);
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
        public void SHA512RSA2048DigitalSignatureVerifyThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            IDigitalSignature digitalSignature = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHARSADigitalSignatureResult signature = digitalSignature.CreateRsaThreadpool(2048, dataToSign);
            bool result = digitalSignature.VerifyRsaThreadpool(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA512ED25519DigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHAED25519DalekDigitialSignatureResult result = wrapper.CreateED25519(dataToSign);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.Signature);
        }

        [Fact]
        public void SHA512ED25519DigitalSignatureThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHAED25519DalekDigitialSignatureResult result = wrapper.CreateED25519Threadpool(dataToSign);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.Signature);
        }

        [Fact]
        public void SHA512ED25519DigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHAED25519DalekDigitialSignatureResult result = wrapper.CreateED25519(dataToSign);
            bool result2 = wrapper.VerifyED25519(result.PublicKey, dataToSign, result.Signature);
            Assert.True(result2);
        }

        [Fact]
        public void SHA512ED25519DigitalSignatureVerifyThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA512);
            SHAED25519DalekDigitialSignatureResult result = wrapper.CreateED25519Threadpool(dataToSign);
            bool result2 = wrapper.VerifyED25519Threadpool(result.PublicKey, dataToSign, result.Signature);
            Assert.True(result2);
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
        public void SHA256RSADigitalSignatureThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsaThreadpool(4096, dataToSign);
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
        public void SHA256RSADigitalSignatureVerifyThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsaThreadpool(4096, dataToSign);
            bool result = wrapper.VerifyRsaThreadpool(signature.PublicKey, dataToSign, signature.Signature);
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

        [Fact]
        public void SHA256RSADigitalSignatureVerifyFailThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsaThreadpool(4096, dataToSign);
            dataToSign = Encoding.UTF8.GetBytes("NOtTheSameData");
            bool result = wrapper.VerifyRsaThreadpool(signature.PublicKey, dataToSign, signature.Signature);
            Assert.False(result);
        }

        [Fact]
        public void SHA256ED25519DalekDigitalSiganture()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHAED25519DalekDigitialSignatureResult signature = wrapper.CreateED25519(dataToSign);
            Assert.NotEmpty(signature.PublicKey);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void SHA256ED25519DalekDigitalSigantureThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHAED25519DalekDigitialSignatureResult signature = wrapper.CreateED25519Threadpool(dataToSign);
            Assert.NotEmpty(signature.PublicKey);
            Assert.NotEmpty(signature.Signature);
        }


        [Fact]
        public void SHA256ED25519DalekVerifyPass()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHAED25519DalekDigitialSignatureResult signature = wrapper.CreateED25519(dataToSign);
            bool result = wrapper.VerifyED25519(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA256ED25519DalekVerifyPassThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHAED25519DalekDigitialSignatureResult signature = wrapper.CreateED25519Threadpool(dataToSign);
            bool result = wrapper.VerifyED25519Threadpool(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA256ED25519DalekVerifyFail()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHAED25519DalekDigitialSignatureResult signature = wrapper.CreateED25519(dataToSign);
            dataToSign = Encoding.UTF8.GetBytes("NotTheSameStuff");
            bool result = wrapper.VerifyED25519(signature.PublicKey, dataToSign, signature.Signature);
            Assert.False(result);
        }

        [Fact]
        public void SHA256ED25519DalekVerifyFailThreadpool()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            IDigitalSignature wrapper = DigitalSignatureFactory.Get(DigitalSignatureRSAType.SHA256);
            SHAED25519DalekDigitialSignatureResult signature = wrapper.CreateED25519Threadpool(dataToSign);
            dataToSign = Encoding.UTF8.GetBytes("NotTheSameStuff");
            bool result = wrapper.VerifyED25519Threadpool(signature.PublicKey, dataToSign, signature.Signature);
            Assert.False(result);
        }
    }
}
