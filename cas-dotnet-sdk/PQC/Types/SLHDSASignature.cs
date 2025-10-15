using System;

namespace CasDotnetSdk.PQC.Types
{
    internal struct SLHDSASignatureStruct
    {
        public IntPtr signature_ptr { get; set; }
        public int signature_length { get; set; }
    }
}
