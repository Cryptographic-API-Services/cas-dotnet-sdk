namespace CasDotnetSdk.DigitalSignature
{
    public enum DigitalSignatureRSAType
    {
        SHA512 = 1,
        SHA256 = 2
    }
    public static class DigitalSignatureFactory
    {
        /// <summary>
        /// Get a digital signature wrapper based off the type provided.
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public static IDigitalSignature Get(DigitalSignatureRSAType type)
        {
            IDigitalSignature signature = null;
            switch (type)
            {
                case DigitalSignatureRSAType.SHA512:
                    signature = new SHA512DigitalSignatureWrapper();
                    break;
                case DigitalSignatureRSAType.SHA256:
                    signature = new SHA256DigitalSignatureWrapper();
                    break;
            }
            return signature;
        }
    }
}
