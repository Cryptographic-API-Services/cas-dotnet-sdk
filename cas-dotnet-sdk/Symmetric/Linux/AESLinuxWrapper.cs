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
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
