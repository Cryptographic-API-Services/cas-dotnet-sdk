using System;

namespace CasDotnetSdk.Hybrid.Types
{
    internal struct HpkeKeyPairResultStruct
    {
        public IntPtr private_key_ptr;
        public long private_key_ptr_length;
        public IntPtr public_key_ptr;
        public long public_key_ptr_length;
        public IntPtr info_str_ptr;
        public long info_str_ptr_length;
    }
}
