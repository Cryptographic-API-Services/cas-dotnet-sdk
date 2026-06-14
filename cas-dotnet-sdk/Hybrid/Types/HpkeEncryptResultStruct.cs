using System;

namespace CasDotnetSdk.Hybrid.Types
{
    internal struct HpkeEncryptResultStruct
    {
        public IntPtr encapped_key_ptr;
        public long encapped_key_ptr_length;
        public IntPtr ciphertext_ptr;
        public long ciphertext_ptr_length;
        public IntPtr tag_ptr;
        public long tag_ptr_length;
        public int error_code;
    }
}
