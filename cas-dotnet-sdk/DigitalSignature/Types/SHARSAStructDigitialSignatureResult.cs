using System;

namespace CasDotnetSdk.DigitalSignature.Types
{
    internal struct SHARSAStructDigitialSignatureResult
    {
        public IntPtr private_key { get; set; }
        public IntPtr public_key { get; set; }
        public IntPtr signature { get; set; }
        public int length { get; set; }
    }
}
