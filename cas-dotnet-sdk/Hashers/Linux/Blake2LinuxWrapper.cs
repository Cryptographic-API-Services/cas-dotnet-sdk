using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Hashers.Blake2Wrapper;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class Blake2LinuxWrapper
    {
        [DllImport("cas_core_lib.so")]
        public static extern IntPtr blake2_512(string toHash);

        [DllImport("cas_core_lib.so")]
        public static extern Blake2HashByteResult blake2_512_bytes(byte[] toHash, int toHashLength);

        [DllImport("cas_core_lib.so")]
        public static extern IntPtr blake2_256(string toHash);

        [DllImport("cas_core_lib.so")]
        public static extern bool blake2_256_verify(string dataToVerify, string hash);

        [DllImport("cas_core_lib.so")]
        public static extern bool blake2_512_verify(string dataToVerify, string hash);

        [DllImport("cas_core_lib.so")]
        public static extern bool blake2_512_bytes_verify(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
