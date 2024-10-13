using System;

namespace CasDotnetSdk.Hybrid.Types
{
    internal struct HpkeEncryptResultStruct
    {
        public IntPtr encapped_key_ptr;
        public int encapped_key_ptr_length;
        public IntPtr ciphertext_ptr;
        public int ciphertext_ptr_length;
        public IntPtr tag_ptr;
        public int tag_ptr_length;
    }
}
