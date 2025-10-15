using System;

namespace CasDotnetSdk.PQC.Types
{
    internal struct SLHDSAKeyPairStruct
    {
        public IntPtr signing_key_ptr { get; set; }
        public int signing_key_length { get; set; }
        public IntPtr verification_key_ptr { get; set; }
        public int verification_key_length { get; set; }
    }

    public class SLHDSAKeyPair
    {
        public byte[] SigningKey { get; set; }
        public byte[] VerificationKey { get; set; }
    }
}
