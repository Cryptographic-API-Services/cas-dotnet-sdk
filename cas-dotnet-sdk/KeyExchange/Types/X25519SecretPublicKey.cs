using System;

namespace CasDotnetSdk.KeyExchange.Types
{
    public class X25519SecretPublicKey
    {
        public byte[] SecretKey { get; set; } = Array.Empty<byte>();
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    }
}
