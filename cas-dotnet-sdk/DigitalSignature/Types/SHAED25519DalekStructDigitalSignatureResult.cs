using System;

namespace CasDotnetSdk.DigitalSignature.Types
{
    internal struct SHAED25519DalekStructDigitalSignatureResult
    {
        public IntPtr public_key { get; set; }
        public int public_key_length { get; set; }
        public IntPtr signature_raw_ptr { get; set; }
        public int signature_length { get; set; }
    }
}
