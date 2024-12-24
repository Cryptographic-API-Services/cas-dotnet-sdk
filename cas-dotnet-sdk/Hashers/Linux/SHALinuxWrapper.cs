using CasDotnetSdk.Hashers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class SHALinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern SHAHashByteResult sha512_bytes_threadpool(byte[] dataToHash, int dataLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify_threadpool(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern SHAHashByteResult sha256_bytes_threadpool(byte[] dataToHash, int dataLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify_threadpool(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);
    }
}
