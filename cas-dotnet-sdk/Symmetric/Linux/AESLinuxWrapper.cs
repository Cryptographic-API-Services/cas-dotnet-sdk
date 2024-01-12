using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdk.Symmetric.Linux
{
    internal static class AESLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr aes_256_key();

        [DllImport("libcas_core_lib.so")]
        public static extern IntPtr aes_128_key();

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_128_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_128_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_256_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_256_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
