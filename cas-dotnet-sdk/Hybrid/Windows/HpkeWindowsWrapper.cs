using System.Runtime.InteropServices;
using CasDotnetSdk.Hybrid.Types;

namespace CasDotnetSdk.Hybrid.Windows
{
    internal static class HpkeWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HpkeKeyPairResultStruct hpke_generate_keypair();


        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HpkeEncryptResultStruct hpke_encrypt(byte[] plaintext, int plainTextLength, byte[] publicKey, int publicKeyLength, byte[] infoStr, int infoStrLength);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HpkeDecryptResultStruct hpke_decrypt(byte[] cipherText, int cipherTextLength, byte[] privateKey, int privateKeyLength, byte[] encappedKey, int encappedKeyLength, byte[] tag, int tagLength, byte[] infoStr, int infoStrLength);
    }
}
