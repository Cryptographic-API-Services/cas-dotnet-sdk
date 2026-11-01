using System;

namespace CasDotnetSdk.PQC.Types
{
    /// <summary>
    /// An ML-DSA-65 (FIPS 204) key pair. The <see cref="SigningKey"/> is the 32-byte
    /// private seed and the <see cref="VerificationKey"/> is the 1952-byte public key.
    /// </summary>
    public class MLDSAKeyPair
    {
        public byte[] SigningKey { get; set; } = Array.Empty<byte>();
        public byte[] VerificationKey { get; set; } = Array.Empty<byte>();
    }
}
