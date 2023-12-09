using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class Blake2LinuxWrapper
    {
        [DllImport("performant_encryption.so")]
        public static extern IntPtr blake2_512(string toHash);
        [DllImport("performant_encryption.so")]
        public static extern IntPtr blake2_256(string toHash);
        [DllImport("performant_encryption.so")]
        public static extern bool blake2_256_verify(string dataToVerify, string hash);
        [DllImport("performant_encryption.so")]
        public static extern bool blake2_512_verify(string dataToVerify, string hash);
        [DllImport("performant_encryption.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
