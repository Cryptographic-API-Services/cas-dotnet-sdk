using System;

namespace CasDotnetSdk.PQC.Types
{
    /// <summary>
    /// The result of an ML-KEM-1024 encapsulation: the <see cref="Ciphertext"/> (1568 bytes)
    /// to send to the holder of the secret key, and the 32-byte <see cref="SharedSecret"/>
    /// the sender derives locally.
    /// </summary>
    public class MLKemEncapsulateResult
    {
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] SharedSecret { get; set; } = Array.Empty<byte>();
    }
}
