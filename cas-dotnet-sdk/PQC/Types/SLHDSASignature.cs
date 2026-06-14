using System;

namespace CasDotnetSdk.PQC.Types
{
    internal struct SLHDSASignatureStruct
    {
        public IntPtr signature_ptr { get; set; }
        public long signature_length { get; set; }
        public int error_code { get; set; }
    }
}
