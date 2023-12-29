using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Hashers.SHAWrapper;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class SHAWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("cas_core_lib.dll")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.dll")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
