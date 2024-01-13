using System;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519ByteSignatureResultStruct
    {
        public IntPtr signature_byte_ptr { get; set; }
        public int signature_length { get; set; }
        public IntPtr public_key { get; set; }
        public int public_key_length { get; set; }
    }
}
