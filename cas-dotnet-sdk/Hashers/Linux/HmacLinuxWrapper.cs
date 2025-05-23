﻿using System.Runtime.InteropServices;
using CasDotnetSdk.Hashers.Types;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class HmacLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HmacSignByteResult hmac_sign_bytes(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HmacSignByteResult hmac_sign_bytes_threadpool(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify_bytes(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify_bytes_threadpool(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);
    }
}
