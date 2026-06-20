using System;

namespace CasDotnetSdk.Signatures.Types
{
    public class Ed25519ByteSignatureResult
    {
        public byte[] Signature { get; set; } = Array.Empty<byte>();
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    }
}
