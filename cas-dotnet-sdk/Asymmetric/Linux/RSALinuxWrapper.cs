using CasDotnetSdk.Asymmetric.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Asymmetric.Linux
{
    internal static class RSALinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern RsaKeyPairStruct get_key_pair(int key_size);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern RsaKeyPairStruct get_key_pair_threadpool(int key_size);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern RsaEncryptBytesResult rsa_encrypt_bytes(string publicKey, byte[] dataToEncrypt, int dataToEncryptLenght);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern RsaEncryptBytesResult rsa_encrypt_bytes_threadpool(string publicKey, byte[] dataToEncrypt, int dataToEncryptLenght);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern RsaDecryptBytesResult rsa_decrypt_bytes(string privateKey, byte[] dataToDecrypt, int dataToDecryptLenght);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern RsaSignBytesResults rsa_sign_with_key_bytes(string privateKey, byte[] dataToSign, int dataToSignLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool rsa_verify_bytes(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
