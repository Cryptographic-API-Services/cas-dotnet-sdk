using System;
using System.Runtime.InteropServices;
using static CasDotnetSdk.Signatures.ED25519Wrapper;

namespace CasDotnetSdk.Signatures.Linux
{
    internal static class ED25519LinuxWrapper
    {
        [DllImport("cas_core_lib.so")]
        public static extern IntPtr get_ed25519_key_pair();

        [DllImport("cas_core_lib.so")]
        public static extern Ed25519KeyPairBytesResultStruct get_ed25519_key_pair_bytes();

        [DllImport("cas_core_lib.so")]
        public static extern Ed25519SignatureStruct sign_with_key_pair(string keyBytes, string dataToSign);

        [DllImport("cas_core_lib.so")]
        public static extern Ed25519ByteSignatureResultStruct sign_with_key_pair_bytes(byte[] keyPair, int keyPairLength, byte[] message, int messageLength);

        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_key_pair(string keyBytes, string signature, string dataToVerify);

        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_key_pair_bytes(byte[] keyPair, int keyPairLength, byte[] signature, int signatureLength, byte[] message, int messageLength);

        [DllImport("cas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_public_key(string publicKey, string signature, string dataToVerify);

        [DllImport("cas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);


        [DllImport("cas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
