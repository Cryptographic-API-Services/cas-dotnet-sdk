using CasDotnetSdk.Hashers.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class SHAWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern SHAHashByteResult sha512_bytes(byte[] dataToHash, int dataLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern SHAHashByteResult sha256_bytes(byte[] dataToHash, int dataLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
