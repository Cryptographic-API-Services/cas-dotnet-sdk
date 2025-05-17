using System.Runtime.InteropServices;
using CasDotnetSdk.Hashers.Types;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class SHAWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern SHAHashByteResult sha512_bytes_threadpool(byte[] dataToHash, int dataLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha512_bytes_verify_threadpool(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern SHAHashByteResult sha256_bytes_threadpool(byte[] dataToHash, int dataLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool sha256_bytes_verify_threadpool(byte[] dataToHash, int dataLength, byte[] hashToVerify, int hashToVerifyLength);
    }
}
