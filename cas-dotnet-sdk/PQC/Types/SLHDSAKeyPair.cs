using System;

namespace CasDotnetSdk.PQC.Types
{
    public class SLHDSAKeyPair
    {
        public byte[] SigningKey { get; set; } = Array.Empty<byte>();
        public byte[] VerificationKey { get; set; } = Array.Empty<byte>();
    }
}
