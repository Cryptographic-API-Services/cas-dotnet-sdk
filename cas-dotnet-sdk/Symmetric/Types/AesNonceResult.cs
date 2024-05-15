using System;

namespace CasDotnetSdk.Symmetric.Types
{
    internal struct AesNonceResult
    {
        public IntPtr nonce { get; set; }
        public int length { get; set; }
    }
}
