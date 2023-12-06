using System.Runtime.InteropServices;
using Xunit;
using static EasDotnetSdk.ED25519Wrapper;

namespace EasDotnetSdk.Tests
{
    public class ED25519WrapperTests
    {
        private readonly ED25519Wrapper _wrapper;
        public ED25519WrapperTests()
        {
            this._wrapper = new ED25519Wrapper();
        }

        [Fact]
        public void GetKeyPair()
        {
            IntPtr keyPairPtr = this._wrapper.GetKeyPair();
            string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
            ED25519Wrapper.free_cstring(keyPairPtr);
            Assert.NotNull(keyPair);
        }

        [Fact]
        public void SignData()
        {
            IntPtr keyPairPtr = this._wrapper.GetKeyPair();
            string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
            Ed25519SignatureResult signedData = this._wrapper.Sign(keyPair, "SignThisData");
            string signature = Marshal.PtrToStringAnsi(signedData.Signature);
            string publicKey = Marshal.PtrToStringAnsi(signedData.Public_Key);
            ED25519Wrapper.free_cstring(keyPairPtr);
            ED25519Wrapper.free_cstring(signedData.Public_Key);
            ED25519Wrapper.free_cstring(signedData.Signature);
            Assert.NotNull(signature);
            Assert.NotNull(publicKey);
        }

        [Fact]
        public void Verify()
        {
            IntPtr keyPairPtr = this._wrapper.GetKeyPair();
            string dataToSign = "TestData12345";
            string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
            Ed25519SignatureResult signatureResult = this._wrapper.Sign(keyPair, dataToSign);
            string signature = Marshal.PtrToStringAnsi(signatureResult.Signature);
            bool isValid = this._wrapper.Verify(keyPair, signature, dataToSign);
            ED25519Wrapper.free_cstring(signatureResult.Signature);
            ED25519Wrapper.free_cstring(signatureResult.Public_Key);
            ED25519Wrapper.free_cstring(keyPairPtr);
            Assert.Equal(true, isValid);
        }

        [Fact]
        public async void VerifyWithPublicKey()
        {
            IntPtr keyPairPtr = this._wrapper.GetKeyPair();
            string dataToSign = "welcomeHome";
            string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
            Ed25519SignatureResult result = this._wrapper.Sign(keyPair, dataToSign);
            string publicKey = Marshal.PtrToStringAnsi(result.Public_Key);
            string siganture = Marshal.PtrToStringAnsi(result.Signature);
            bool isValid = this._wrapper.VerifyWithPublicKey(publicKey, siganture, dataToSign);
            ED25519Wrapper.free_cstring(keyPairPtr);
            ED25519Wrapper.free_cstring(result.Public_Key);
            ED25519Wrapper.free_cstring(result.Signature);
            Assert.Equal(true, isValid);
        }
    }
}