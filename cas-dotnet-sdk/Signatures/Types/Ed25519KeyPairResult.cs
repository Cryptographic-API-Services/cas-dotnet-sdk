using System;

namespace CasDotnetSdk.Signatures.Types
{
    public class Ed25519KeyPairResult
    {
        public byte[] SigningKey { get; set; } = Array.Empty<byte>();
        public byte[] VerifyingKey { get; set; } = Array.Empty<byte>();
    }
}
