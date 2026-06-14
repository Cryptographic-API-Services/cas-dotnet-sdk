using System;

namespace CasDotnetSdk.Asymmetric.Types
{
    internal struct RsaSignBytesResults
    {
        public IntPtr signature_raw_ptr;
        public long length;
        public int error_code;
    }
}
