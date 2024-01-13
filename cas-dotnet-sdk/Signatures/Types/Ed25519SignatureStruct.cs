using System;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519SignatureStruct
    {
        public IntPtr Signature { get; set; }
        public IntPtr Public_Key { get; set; }
    }
}
