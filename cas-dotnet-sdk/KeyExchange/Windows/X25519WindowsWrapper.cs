using System.Runtime.InteropServices;
using CasDotnetSdk.KeyExchange.Types;

namespace CasDotnetSdk.KeyExchange.Windows
{
    internal static class X25519WindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern X25519SecretPublicKeyResult generate_secret_and_public_key();

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern X25519SharedSecretResult diffie_hellman(byte[] secretKey, int secretKeyLength, byte[] otherUserPublicKey, int otherUserPublickKeyLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern X25519SecretPublicKeyResult generate_secret_and_public_key_threadpool();

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern X25519SharedSecretResult diffie_hellman_threadpool(byte[] secretKey, int secretKeyLength, byte[] otherUserPublicKey, int otherUserPublickKeyLength);
    }
}
