using CasDotnetSdk.Symmetric.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Symmetric.Linux
{
    internal static class AESLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern AesNonceResult aes_nonce();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern IntPtr aes_256_key();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern IntPtr aes_128_key();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_128_encrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_128_decrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_256_encrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_256_decrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Aes256KeyAndNonceX25519DiffieHellmanStruct aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(byte[] sharedSecret, int sharedSecretLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Aes256KeyAndNonceX25519DiffieHellmanStruct aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(byte[] sharedSecret, int sharedSecretLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
