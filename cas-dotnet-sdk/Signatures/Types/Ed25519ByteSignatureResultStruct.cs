using System;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519ByteSignatureResultStruct
    {
        public IntPtr signature_byte_ptr { get; set; }
        public long signature_length { get; set; }
        public IntPtr public_key { get; set; }
        public long public_key_length { get; set; }
        public int error_code { get; set; }
    }
}
