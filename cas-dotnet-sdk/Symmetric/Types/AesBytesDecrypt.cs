using System;

namespace CasDotnetSdk.Symmetric.Types
{
    internal struct AesBytesDecrypt
    {
        public IntPtr plaintext { get; set; }
        public long length { get; set; }
        public int error_code { get; set; }
    }
}
