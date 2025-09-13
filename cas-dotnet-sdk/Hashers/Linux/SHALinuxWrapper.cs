using CasDotnetSdk.Hashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class SHALinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("libcas_core_lib.so")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);
    }
}
