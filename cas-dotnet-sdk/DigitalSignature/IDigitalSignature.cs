using CasDotnetSdk.DigitalSignature.Types;

namespace CasDotnetSdk.DigitalSignature
{
    public interface IDigitalSignature
    {
        public SHARSADigitalSignatureResult CreateRsa(int rsaKeySize, byte[] dataToSign);
        public bool VerifyRsa(string publicKey, byte[] dataToVerify, byte[] signature);
        public SHAED25519DalekDigitialSignatureResult CreateED25519(byte[] dataToSign);
        public bool VerifyED25519(byte[] publicKey, byte[] dataToVerify, byte[] signature);
    }
}
