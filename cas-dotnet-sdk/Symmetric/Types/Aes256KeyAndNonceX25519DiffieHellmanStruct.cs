using System;

namespace CasDotnetSdk.Symmetric.Types
{
    internal struct Aes256KeyAndNonceX25519DiffieHellmanStruct
    {
        public IntPtr aes_key_ptr;
        public IntPtr aes_nonce_ptr;
        public int aes_nonce_ptr_length;
    }
}
