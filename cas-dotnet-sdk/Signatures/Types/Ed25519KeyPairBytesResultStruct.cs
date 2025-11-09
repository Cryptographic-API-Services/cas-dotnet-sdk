using System;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519KeyPairBytesResultStruct
    {
        public IntPtr signing_key { get; set; }
        public int signing_key_length { get; set; }
        public IntPtr verifying_key { get; set; }
        public int verifying_key_length { get; set; }
    }
}
