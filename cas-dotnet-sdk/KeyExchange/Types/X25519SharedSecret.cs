using System;

namespace CasDotnetSdk.KeyExchange.Types
{
    public class X25519SharedSecret
    {
        public byte[] SharedSecret { get; set; } = Array.Empty<byte>();
    }
}