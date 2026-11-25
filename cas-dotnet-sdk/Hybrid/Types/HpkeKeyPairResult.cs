using System;

namespace CasDotnetSdk.Hybrid.Types
{
    public class HpkeKeyPairResult
    {
        public byte[] PrivateKey { get; set; } = Array.Empty<byte>();
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
        /// <summary>
        /// A random RFC 9180 <c>info</c> value, generated for convenience. It is application
        /// context both sides agree on, not part of the key pair; any agreed bytes work.
        /// </summary>
        public byte[] InfoStr { get; set; } = Array.Empty<byte>();
    }
}
