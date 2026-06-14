using System;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519KeyPairBytesResultStruct
    {
        public IntPtr signing_key { get; set; }
        public long signing_key_length { get; set; }
        public IntPtr verifying_key { get; set; }
        public long verifying_key_length { get; set; }
    }
}
