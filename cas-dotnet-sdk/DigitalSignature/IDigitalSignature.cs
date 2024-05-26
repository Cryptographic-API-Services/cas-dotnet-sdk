using CasDotnetSdk.DigitalSignature.Types;

namespace CasDotnetSdk.DigitalSignature
{
    public interface IDigitalSignature
    {
        public SHARSADigitalSignatureResult CreateRsa(int rsaKeySize, byte[] dataToSign);
        public SHARSADigitalSignatureResult CreateRsaThreadpool(int rsaKeySize, byte[] dataToSign);
        public bool VerifyRsa(string publicKey, byte[] dataToVerify, byte[] signature);
        public bool VerifyRsaThreadpool(string publicKey, byte[] dataToVerify, byte[] signature);
        public SHAED25519DalekDigitialSignatureResult CreateED25519(byte[] dataToSign);
        public SHAED25519DalekDigitialSignatureResult CreateED25519Threadpool(byte[] dataToSign);
        public bool VerifyED25519(byte[] publicKey, byte[] dataToVerify, byte[] signature);
        public bool VerifyED25519Threadpool(byte[] publicKey, byte[] dataToVerify, byte[] signature);
    }
}
