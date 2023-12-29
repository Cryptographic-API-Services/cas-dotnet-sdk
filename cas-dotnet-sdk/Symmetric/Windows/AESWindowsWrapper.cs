using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Symmetric.AESWrapper;

namespace CasDotnetSdk.Symmetric.Windows
{
    internal static class AESWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes_256_key();

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr aes_128_key();

        [DllImport("cas_core_lib.dll")]
        public static extern AesBytesEncrypt aes_128_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("cas_core_lib.dll")]
        public static extern AesBytesDecrypt aes_128_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("cas_core_lib.dll")]
        public static extern AesBytesEncrypt aes_256_encrypt_bytes_with_key(string nonceKey, string key, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("cas_core_lib.dll")]
        public static extern AesBytesDecrypt aes_256_decrypt_bytes_with_key(string nonceKey, string key, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
