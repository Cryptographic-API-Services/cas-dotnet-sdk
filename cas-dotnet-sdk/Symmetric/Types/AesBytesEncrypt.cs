using System;

namespace CasDotnetSdk.Symmetric.Types
{
    internal struct AesBytesEncrypt
    {
        public IntPtr ciphertext { get; set; }
        public int length { get; set; }
        public int error_code { get; set; }
    }
}
