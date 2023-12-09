using CasDotnetSdk.Helpers;
using CasDotnetSdk.Signatures;
using System.Runtime.InteropServices;
using Xunit;
using static CasDotnetSdk.Signatures.ED25519Wrapper;

namespace CasDotnetSdkTests.Tests
{
    public class ED25519WrapperTests
    {
        private readonly ED25519Wrapper _wrapper;
        private readonly OperatingSystemDeterminator _operatingSystem;
        public ED25519WrapperTests()
        {
            this._wrapper = new ED25519Wrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void GetKeyPair()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string keyPair = this._wrapper.GetKeyPair();
                Assert.NotNull(keyPair);
            }
        }

        [Fact]
        public void SignData()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string keyPair = this._wrapper.GetKeyPair();
                Ed25519SignatureResult signedData = this._wrapper.Sign(keyPair, "SignThisData");
                Assert.NotNull(signedData.Signature);
                Assert.NotNull(signedData.PublicKey);
            }
        }

        [Fact]
        public void Verify()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string keyPair = this._wrapper.GetKeyPair();
                string dataToSign = "TestData12345";
                Ed25519SignatureResult signatureResult = this._wrapper.Sign(keyPair, dataToSign);
                bool isValid = this._wrapper.Verify(keyPair, signatureResult.Signature, dataToSign);
                Assert.Equal(true, isValid);
            }
        }

        [Fact]
        public async void VerifyWithPublicKey()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string keyPair = this._wrapper.GetKeyPair();
                string dataToSign = "welcomeHome";
                Ed25519SignatureResult result = this._wrapper.Sign(keyPair, dataToSign);
                bool isValid = this._wrapper.VerifyWithPublicKey(result.PublicKey, result.Signature, dataToSign);
                Assert.Equal(true, isValid);
            }
        }
    }
}