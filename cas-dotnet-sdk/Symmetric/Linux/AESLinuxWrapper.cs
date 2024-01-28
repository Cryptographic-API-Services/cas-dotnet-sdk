using CasDotnetSdk.Symmetric.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Symmetric.Linux
{
    internal static class AESLinuxWrapper
    {
        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern IntPtr aes_256_key();

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern IntPtr aes_128_key();

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_128_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_128_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_256_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_256_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents\\libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
