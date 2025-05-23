﻿using System.Runtime.InteropServices;
using CasDotnetSdk.Asymmetric.Types;

namespace CasDotnetSdk.Asymmetric.Windows
{
    internal static class RSAWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern RsaKeyPairStruct get_key_pair(int key_size);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern RsaKeyPairStruct get_key_pair_threadpool(int key_size);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern RsaSignBytesResults rsa_sign_with_key_bytes(string privateKey, byte[] dataToSign, int dataToSignLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern RsaSignBytesResults rsa_sign_with_key_bytes_threadpool(string privateKey, byte[] dataToSign, int dataToSignLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool rsa_verify_bytes(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool rsa_verify_bytes_threadpool(string publicKey, byte[] dataToVerify, int dataToVerifyLength, byte[] signature, int signatureLength);
    }
}
