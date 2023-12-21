using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdk.Symmetric.Linux
{
    internal static class AESLinuxWrapper
    {
        [DllImport("cas_core_lib.so")]
        public static extern AesEncryptStruct aes256_encrypt_string(string nonceKey, string dataToEncrypt);

        [DllImport("cas_core_lib.so")]
        public static extern AesEncryptStruct aes128_encrypt_string(string nonceKey, string dataToEncrypt);

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr aes256_decrypt_string(string nonceKey, string key, string dataToDecrypt);

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr aes_256_key();

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr aes_128_key();

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr aes256_encrypt_string_with_key(string nonceKey, string key, string dataToEncrypt);

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr aes_128_encrypt_string_with_key(string nonceKey, string key, string dataToEncrypt);

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr aes128_decrypt_string(string nonceKey, string key, string dataToEncrypt);

        [DllImport("cas_core_lib.so")]
        public static extern AesBytesEncrypt aes_128_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("cas_core_lib.so")]
        public static extern AesBytesDecrypt aes_128_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("cas_core_lib.so")]
        public static extern AesBytesEncrypt aes_256_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("cas_core_lib.so")]
        public static extern AesBytesDecrypt aes_256_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
