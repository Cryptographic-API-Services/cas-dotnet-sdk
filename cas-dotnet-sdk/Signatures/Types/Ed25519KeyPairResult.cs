namespace CasDotnetSdk.Signatures.Types
{
    public class Ed25519KeyPairResult
    {
        public byte[] SigningKey { get;set; }
        public byte[] VerifyingKey { get; set; }
    }
}
