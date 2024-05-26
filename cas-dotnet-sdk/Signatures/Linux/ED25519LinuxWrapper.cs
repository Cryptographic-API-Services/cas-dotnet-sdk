using CasDotnetSdk.Signatures.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures.Linux
{
    internal static class ED25519LinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ed25519KeyPairBytesResultStruct get_ed25519_key_pair_bytes();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ed25519ByteSignatureResultStruct sign_with_key_pair_bytes(byte[] keyPair, int keyPairLength, byte[] message, int messageLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_key_pair_bytes(byte[] keyPair, int keyPairLength, byte[] signature, int signatureLength, byte[] message, int messageLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_public_key_bytes(byte[] publicKey, int publicKeyLength, byte[] signature, int signatureLength, byte[] dataToVerify, int dataToVerifyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ed25519KeyPairBytesResultStruct get_ed25519_key_pair_bytes_threadpool();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ed25519ByteSignatureResultStruct sign_with_key_pair_bytes_threadpool(byte[] keyPair, int keyPairLength, byte[] message, int messageLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_key_pair_bytes_threadpool(byte[] keyPair, int keyPairLength, byte[] signature, int signatureLength, byte[] message, int messageLength);

        [DllImport("Contents/libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_public_key_bytes_threadpool(byte[] publicKey, int publicKeyLength, byte[] signature, int signatureLength, byte[] dataToVerify, int dataToVerifyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
