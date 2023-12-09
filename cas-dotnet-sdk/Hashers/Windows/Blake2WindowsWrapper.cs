using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class Blake2WindowsWrapper
    {
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr blake2_512(string toHash);
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr blake2_256(string toHash);
        [DllImport("performant_encryption.dll")]
        public static extern bool blake2_256_verify(string dataToVerify, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern bool blake2_512_verify(string dataToVerify, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
