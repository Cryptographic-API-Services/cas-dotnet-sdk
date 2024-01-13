using System;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519KeyPairBytesResultStruct
    {
        public IntPtr key_pair { get; set; }
        public int length { get; set; }
    }
}
