using System;

namespace CasDotnetSdk.Hybrid.Types
{
    public class HpkeEncryptResult
    {
        public byte[] EncappedKey { get; set; } = Array.Empty<byte>();
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] Tag { get; set; } = Array.Empty<byte>();
    }
}
