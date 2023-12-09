using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Asymmetric.RSAWrapper;

namespace CasDotnetSdk.Asymmetric.Windows
{
    internal static class RSAWindowsWrapper
    {
        [DllImport("performant_encryption.dll")]
        public static extern RustRsaKeyPairStruct get_key_pair(int key_size);
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr rsa_encrypt(string publicKey, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr rsa_decrypt(string privateKey, string dataToDecrypt);
        [DllImport("performant_encryption.dll")]
        public static extern RsaSignResultStruct rsa_sign(string dataToSign, int keySize);
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr rsa_sign_with_key(string privateKey, string dataToSign);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool rsa_verify(string publicKey, string dataToVerify, string signature);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
