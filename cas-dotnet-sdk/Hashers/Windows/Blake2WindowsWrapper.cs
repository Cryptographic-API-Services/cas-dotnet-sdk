using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class Blake2WindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr blake2_512(string toHash);
        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr blake2_256(string toHash);
        [DllImport("cas_core_lib.dll")]
        public static extern bool blake2_256_verify(string dataToVerify, string hash);
        [DllImport("cas_core_lib.dll")]
        public static extern bool blake2_512_verify(string dataToVerify, string hash);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
