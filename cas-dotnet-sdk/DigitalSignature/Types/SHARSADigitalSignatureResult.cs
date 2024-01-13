namespace CasDotnetSdk.DigitalSignature.Types
{
    public class SHARSADigitalSignatureResult
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public byte[] Signature { get; set; }
    }
}
