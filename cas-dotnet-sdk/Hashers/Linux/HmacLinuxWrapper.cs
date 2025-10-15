using CasDotnetSdk.Hashers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class HmacLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern HmacSignByteResult hmac_sign_bytes(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify_bytes(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);
    }
}
