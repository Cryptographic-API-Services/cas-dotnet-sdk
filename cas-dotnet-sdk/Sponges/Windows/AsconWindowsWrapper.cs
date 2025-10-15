using CasDotnetSdk.Sponges.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Sponges.Windows
{
    internal static class AsconWindowsWrapper
    {
        [DllImport("cas_core_lib.dll")]
        public static extern Ascon128KeyStruct ascon_128_key();

        [DllImport("cas_core_lib.dll")]
        public static extern Ascon128NonceStruct ascon_128_nonce();

        [DllImport("cas_core_lib.dll")]
        public static extern Ascon128EncryptResultStruct ascon_128_encrypt(byte[] nonce, int nonceLength, byte[] key, int keyLength, byte[] toEncrypt, int toEncryptLength);

        [DllImport("cas_core_lib.dll")]
        public static extern Ascon128DecryptResultStruct ascon_128_decrypt(byte[] nonce, int nonceLength, byte[] key, int keyLength, byte[] toDecrypt, int toDecryptLength);
    }
}
