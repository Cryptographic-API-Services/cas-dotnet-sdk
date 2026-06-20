using System;

namespace CasDotnetSdk.Hybrid.Types
{
    public class HpkeKeyPairResult
    {
        public byte[] PrivateKey { get; set; } = Array.Empty<byte>();
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
        public byte[] InfoStr { get; set; } = Array.Empty<byte>();
    }
}
