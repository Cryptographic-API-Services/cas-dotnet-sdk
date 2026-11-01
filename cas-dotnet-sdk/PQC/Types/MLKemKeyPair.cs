using System;

namespace CasDotnetSdk.PQC.Types
{
    /// <summary>
    /// An ML-KEM-1024 (FIPS 203) key pair. The <see cref="SecretKey"/> is the 3168-byte
    /// decapsulation key and the <see cref="PublicKey"/> is the 1568-byte encapsulation key.
    /// </summary>
    public class MLKemKeyPair
    {
        public byte[] SecretKey { get; set; } = Array.Empty<byte>();
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    }
}
