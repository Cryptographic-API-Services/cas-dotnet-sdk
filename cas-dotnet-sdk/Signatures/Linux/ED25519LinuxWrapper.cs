using CasDotnetSdk.Signatures.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures.Linux
{
    internal static class ED25519LinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern Ed25519KeyPairBytesResultStruct get_ed25519_key_pair_bytes();

        [DllImport("libcas_core_lib.so")]
        public static extern Ed25519ByteSignatureResultStruct sign_with_key_pair_bytes(byte[] keyPair, int keyPairLength, byte[] message, int messageLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_key_pair_bytes(byte[] keyPair, int keyPairLength, byte[] signature, int signatureLength, byte[] message, int messageLength);

        [DllImport("libcas_core_lib.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_public_key_bytes(byte[] publicKey, int publicKeyLength, byte[] signature, int signatureLength, byte[] dataToVerify, int dataToVerifyLength);
    }
}
