using CasDotnetSdk.Sponges.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Sponges.Linux
{
    internal static class AsconLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128KeyStruct ascon_128_key();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128NonceStruct ascon_128_nonce();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128EncryptResultStruct ascon_128_encrypt(byte[] nonce, int NonceLength, byte[] key, int keyLength, byte[] toEncrypt, int toEncryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128DecryptResultStruct ascon_128_decrypt(byte[] nonce, int nonceLength, byte[] key, int keyLength, byte[] toDecrypt, int toDecryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128KeyStruct ascon_128_key_threadpool();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128NonceStruct ascon_128_nonce_threadpool();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128EncryptResultStruct ascon_128_encrypt_threadpool(byte[] nonce, int NonceLength, byte[] key, int keyLength, byte[] toEncrypt, int toEncryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128DecryptResultStruct ascon_128_decrypt_threadpool(byte[] nonce, int nonceLength, byte[] key, int keyLength, byte[] toDecrypt, int toDecryptLength);
    }
}
