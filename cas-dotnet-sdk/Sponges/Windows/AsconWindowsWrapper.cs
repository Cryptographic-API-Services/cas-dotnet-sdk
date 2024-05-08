using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Sponges.Windows
{
    public static class AsconWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr ascond_128_key();

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr ascond_128_nonce();

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr ascond_128_encrypt(string nonce, string key, byte[] toEncrypt, int toEncryptLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr ascond_128_decrypt(string nonce, string key, byte[] toDecrypt, int toDecryptLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
