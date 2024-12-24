using CasDotnetSdk.Hashers.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers.Windows
{
    internal static class HmacWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HmacSignByteResult hmac_sign_bytes(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HmacSignByteResult hmac_sign_bytes_threadpool(byte[] key, int keyLength, byte[] message, int messageLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify_bytes(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool hmac_verify_bytes_threadpool(byte[] key, int keyLength, byte[] message, int messageLength, byte[] signature, int signatureLength);
    }
}
