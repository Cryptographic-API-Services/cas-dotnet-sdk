using CasDotnetSdk.DigitalSignature.Types;

namespace CasDotnetSdk.DigitalSignature
{
    public interface IDigitalSignature
    {
        public SHARSADigitalSignatureResult CreateRsa(int rsaKeySize, byte[] dataToSign);
        public bool VerifyRsa(string publicKey, byte[] dataToVerify, byte[] signature);
    }
}
