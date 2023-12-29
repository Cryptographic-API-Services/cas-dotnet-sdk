using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Hashers.HmacWrapper;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class HmacLinuxWrapper
    {
        [DllImport("cas_core_lib.so")]
        public static extern HmacSignByteResult hmac_sign_bytes(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify_bytes(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);

        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("cas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
