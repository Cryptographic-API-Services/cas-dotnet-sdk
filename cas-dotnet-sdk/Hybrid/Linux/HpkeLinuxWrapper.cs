﻿using System.Runtime.InteropServices;
using CasDotnetSdk.Hybrid.Types;

namespace CasDotnetSdk.Hybrid.Linux
{
    internal static class HpkeLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HpkeKeyPairResultStruct hpke_generate_keypair();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HpkeEncryptResultStruct hpke_encrypt(byte[] plaintext, int plainTextLength, byte[] publicKey, int publicKeyLength, byte[] infoStr, int infoStrLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern HpkeDecryptResultStruct hpke_decrypt(byte[] cipherText, int cipherTextLength, byte[] privateKey, int privateKeyLength, byte[] encappedKey, int encappedKeyLength, byte[] tag, int tagLength, byte[] infoStr, int infoStrLength);
    }
}
