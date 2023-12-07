using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using EasDotnetSdk.Helpers;

namespace EasDotnetSdk
{
    public class RSAWrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;

        public RSAWrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }
        public struct RustRsaKeyPair
        {
            public IntPtr pub_key;
            public IntPtr priv_key;
        }
        public struct RsaSignResult
        {
            public IntPtr signature;
            public IntPtr public_key;
        }

        [DllImport("performant_encryption.dll")]
        private static extern RustRsaKeyPair get_key_pair(int key_size);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr rsa_encrypt(string publicKey, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr rsa_decrypt(string privateKey, string dataToDecrypt);
        [DllImport("performant_encryption.dll")]
        private static extern RsaSignResult rsa_sign(string dataToSign, int keySize);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr rsa_sign_with_key(string privateKey, string dataToSign);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool rsa_verify(string publicKey, string dataToVerify, string signature);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public IntPtr RsaSignWithKey(string privateKey, string dataToSign)
        {
            if (string.IsNullOrEmpty(privateKey))
            {
                throw new Exception("You must provide a private key to sign your data");
            }
            if (string.IsNullOrEmpty(dataToSign))
            {
                throw new Exception("You must provide data to sign with the private key");
            }

            

        }
        public bool RsaVerify(string publicKey, string dataToVerify, string signature)
        {
            if (string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("You must provide a public key to verify the rsa signature");
            }
            if (string.IsNullOrEmpty(dataToVerify))
            {
                throw new Exception("You must provide the original data to verify the rsa signature");
            }
            if (string.IsNullOrEmpty(dataToVerify))
            {
                throw new Exception("You must provide that digital signature that was provided by our signing");
            }
            return rsa_verify(publicKey, dataToVerify, signature);
        }

        public RsaSignResult RsaSign(string dataToSign, int keySize)
        {
            if (string.IsNullOrEmpty(dataToSign))
            {
                throw new Exception("You must provide data to sign with RSA");
            }
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new Exception("You must provide a valid key bit size to sign with RSA");
            }
            return rsa_sign(dataToSign, keySize);
        }
        public IntPtr RsaDecrypt(string privateKey, string dataToDecrypt)
        {
            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(dataToDecrypt))
            {
                throw new Exception("You need to provide a private key and data to decrypt to use RsaCrypt");
            }
            return rsa_decrypt(privateKey, dataToDecrypt);
        }

        public IntPtr RsaEncrypt(string publicKey, string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(dataToEncrypt))
            {
                throw new Exception("You need to provide a public key and data to encrypt to use RsaEncrypt");
            }
            return rsa_encrypt(publicKey, dataToEncrypt);
        }

        public RustRsaKeyPair GetKeyPair(int keySize)
        {
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new Exception("Please pass in a valid key size.");
            }
            return get_key_pair(keySize);
        }
    }
}
