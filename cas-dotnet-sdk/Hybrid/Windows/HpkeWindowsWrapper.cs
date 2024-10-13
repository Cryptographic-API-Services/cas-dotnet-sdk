using CasDotnetSdk.Hybrid.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hybrid.Windows
{
    internal static class HpkeWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HpkeKeyPairResultStruct hpke_generate_keypair();


        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HpkeEncryptResultStruct hpke_encrypt(byte[] plaintext, int plainTextLength, byte[] publicKey, int publicKeyLength, byte[] infoStr, int infoStrLength);
    }
}
