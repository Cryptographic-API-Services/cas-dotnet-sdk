using CasDotnetSdk.PQC;
using Xunit;

namespace CasDotnetSdkTests
{
    public class SLHDSAWrapperTests
    {
        private readonly SLHDSAWrapper _wrapper;

        public SLHDSAWrapperTests()
        {
            this._wrapper = new SLHDSAWrapper();
        }

        [Fact]
        public void GenerateKeyPair()
        {
            var keyPair = this._wrapper.GenerateSigningAndVerificationKey();
            Assert.NotNull(keyPair);
            Assert.NotNull(keyPair.SigningKey);
            Assert.NotNull(keyPair.VerificationKey);
            Assert.True(keyPair.SigningKey.Length > 0);
            Assert.True(keyPair.VerificationKey.Length > 0);
        }

        [Fact]
        public void SignAndVerify()
        {
            var keyPair = this._wrapper.GenerateSigningAndVerificationKey();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("This is a test message.");
            byte[] signature = this._wrapper.Sign(keyPair.SigningKey, message);
            Assert.NotNull(signature);
            Assert.True(signature.Length > 0);
            bool isValid = this._wrapper.Verify(keyPair.VerificationKey, signature, message);
            Assert.True(isValid);
            // Test with a modified message
            byte[] modifiedMessage = System.Text.Encoding.UTF8.GetBytes("This is a modified test message.");
            bool isModifiedValid = this._wrapper.Verify(keyPair.VerificationKey, signature, modifiedMessage);
            Assert.False(isModifiedValid);
        }
    }
}
