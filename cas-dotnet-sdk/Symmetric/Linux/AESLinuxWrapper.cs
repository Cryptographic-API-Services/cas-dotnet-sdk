using CasDotnetSdk.Symmetric.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Symmetric.Linux
{
    internal static class AESLinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern AesNonceResult aes_nonce();


        [DllImport("libcas_core_lib.so")]
        public static extern AesKeyResult aes_256_key();

        [DllImport("libcas_core_lib.so")]
        public static extern AesKeyResult aes_128_key();


        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_128_encrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, byte[] key, int keyLength, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_128_decrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, byte[] key, int keyLength, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesEncrypt aes_256_encrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, byte[] key, int keyLength, byte[] dataToEncrypt, int dataToEncryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesBytesDecrypt aes_256_decrypt_bytes_with_key(byte[] nonceKey, int nonceKeyLength, byte[] key, int keyLength, byte[] dataToDecrypt, int dataToDecryptLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesKeyX25519DiffieHellmanStruct aes_256_key_from_x25519_diffie_hellman_shared_secret(byte[] sharedSecret, int sharedSecretLength);

        [DllImport("libcas_core_lib.so")]
        public static extern AesKeyX25519DiffieHellmanStruct aes_128_key_from_x25519_diffie_hellman_shared_secret(byte[] sharedSecret, int sharedSecretLength);
    }
}
