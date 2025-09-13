using CasDotnetSdk.Hashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class SHAWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("cas_core_lib.dll")]
        public static extern SHAHashByteResult sha512_bytes_threadpool(byte[] dataToHash, int dataLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify_threadpool(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("cas_core_lib.dll")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("cas_core_lib.dll")]
        public static extern SHAHashByteResult sha256_bytes_threadpool(byte[] dataToHash, int dataLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify_threadpool(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);
    }
}
