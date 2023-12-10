using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Asymmetric.RSAWrapper;

namespace CasDotnetSdk.Asymmetric.Windows
{
    internal static class RSAWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern RustRsaKeyPairStruct get_key_pair(int key_size);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr rsa_encrypt(string publicKey, string dataToEncrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr rsa_decrypt(string privateKey, string dataToDecrypt);
        [DllImport("cas_core_lib.dll")]
        public static extern RsaSignResultStruct rsa_sign(string dataToSign, int keySize);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr rsa_sign_with_key(string privateKey, string dataToSign);
        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool rsa_verify(string publicKey, string dataToVerify, string signature);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
