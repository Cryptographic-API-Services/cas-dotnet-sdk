namespace CasDotnetSdk.DigitalSignature
{
    public enum DigitalSignatureRSAType
    {
        SHA512ARSA = 1,
        SHA256RSA = 2
    }
    public static class DigitalSignatureFactory
    {
        public static ISHADigitalSignature GetRSA(DigitalSignatureRSAType type)
        {
            ISHADigitalSignature signature = null;
            switch(type)
            {
                case DigitalSignatureRSAType.SHA512ARSA:
                    signature = new SHA512DigitalSignatureWrapper();
                    break;
                case DigitalSignatureRSAType.SHA256RSA:
                    break;
            }
            return signature;
        }
    }
}
