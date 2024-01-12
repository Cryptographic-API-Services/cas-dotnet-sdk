using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Hashers.SHAWrapper;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class SHALinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("libcas_core_lib.so")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
