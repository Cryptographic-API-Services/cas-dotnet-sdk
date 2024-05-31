using CasDotnetSdk.Hashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class Blake2WindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern Blake2HashByteResult blake2_512_bytes(byte[] toHash, int toHashLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern Blake2HashByteResult blake2_512_bytes_threadpool(byte[] toHash, int toHashLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern Blake2HashByteResult blake2_256_bytes(byte[] toHash, int toHashLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern Blake2HashByteResult blake2_256_bytes_threadpool(byte[] toHash, int toHashLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern bool blake2_256_bytes_verify(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern bool blake2_256_bytes_verify_threadpool(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern bool blake2_512_bytes_verify(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern bool blake2_512_bytes_verify_threadpool(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);
    }
}
