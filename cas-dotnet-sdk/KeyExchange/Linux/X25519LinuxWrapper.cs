using CasDotnetSdk.KeyExchange.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.KeyExchange.Linux
{
    internal static class X25519LinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern X25519SecretPublicKeyResult generate_secret_and_public_key();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern X25519SharedSecretResult diffie_hellman(byte[] secretKey, int secretKeyLength, byte[] otherUserPublicKey, int otherUserPublickKeyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern X25519SecretPublicKeyResult generate_secret_and_public_key_threadpool();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern X25519SharedSecretResult diffie_hellman_threadpool(byte[] secretKey, int secretKeyLength, byte[] otherUserPublicKey, int otherUserPublickKeyLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
