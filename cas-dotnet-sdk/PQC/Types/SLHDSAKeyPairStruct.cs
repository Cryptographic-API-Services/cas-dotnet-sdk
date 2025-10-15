namespace CasDotnetSdk.PQC.Types
{
    public struct SLHDSAKeyPairStruct
    {
        public byte[] signing_key_ptr { get; set; }
        public int signing_key_length { get; set; }
        public byte[] VerificationKey { get; set; }
        public int verification_key_length { get; set; }
    }
}
