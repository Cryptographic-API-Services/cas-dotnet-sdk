using CasDotnetSdk.DigitalSignature.Types;

namespace CasDotnetSdk.DigitalSignature
{
    public interface ISHADigitalSignature
    {
        public SHARSADigitalSignatureResult Create(int rsaKeySize, byte[] dataToSign);
        public bool Verify(string publicKey, byte[] dataToVerify, byte[] signature);
    }
}
