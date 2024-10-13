using CasDotnetSdk.Hybrid.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hybrid.Linux
{
    internal static class HpkeLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HpkeKeyPairResultStruct hpke_generate_keypair();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HpkeEncryptResultStruct hpke_encrypt(byte[] plaintext, int plainTextLength, byte[] publicKey, int publicKeyLength, byte[] infoStr, int infoStrLength);
    }
}
