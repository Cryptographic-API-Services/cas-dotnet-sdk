using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Asymmetric
{
    public class RSAWrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;
        public RSAWrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        public class RsaKeyPairResult
        {
            public string PublicKey { get; set; }
            public string PrivateKey { get; set; }
        }

        public class RsaSignResult
        {
            public string Signature { get; set; }
            public string PublicKey { get; set; }
        }

        private struct RustRsaKeyPairStruct
        {
            public IntPtr pub_key;
            public IntPtr priv_key;
        }
        private struct RsaSignResultStruct
        {
            public IntPtr signature;
            public IntPtr public_key;
        }

        [DllImport("performant_encryption.dll")]
        private static extern RustRsaKeyPairStruct get_key_pair(int key_size);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr rsa_encrypt(string publicKey, string dataToEncrypt);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr rsa_decrypt(string privateKey, string dataToDecrypt);
        [DllImport("performant_encryption.dll")]
        private static extern RsaSignResultStruct rsa_sign(string dataToSign, int keySize);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr rsa_sign_with_key(string privateKey, string dataToSign);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool rsa_verify(string publicKey, string dataToVerify, string signature);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public string RsaSignWithKey(string privateKey, string dataToSign)
        {
            if (string.IsNullOrEmpty(privateKey))
            {
                throw new Exception("You must provide a private key to sign your data");
            }
            if (string.IsNullOrEmpty(dataToSign))
            {
                throw new Exception("You must provide data to sign with the private key");
            }

            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr signedPtr = rsa_sign_with_key(privateKey, dataToSign);
            string signed = Marshal.PtrToStringAnsi(signedPtr);
            RSAWrapper.free_cstring(signedPtr);
            return signed;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            RsaSignResultStruct resultPtrStruct = rsa_sign(dataToSign, keySize);
            RsaSignResult signed = new RsaSignResult()
            {
                PublicKey = Marshal.PtrToStringAnsi(resultPtrStruct.public_key),
                Signature = Marshal.PtrToStringAnsi(resultPtrStruct.signature)
            };
            RSAWrapper.free_cstring(resultPtrStruct.public_key);
            RSAWrapper.free_cstring(resultPtrStruct.signature);
            return signed;
        }
        public string RsaDecrypt(string privateKey, string dataToDecrypt)
        {
            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(dataToDecrypt))
            {
                throw new Exception("You need to provide a private key and data to decrypt to use RsaCrypt");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr decryptPtr = rsa_decrypt(privateKey, dataToDecrypt);
            string decrypt = Marshal.PtrToStringAnsi(decryptPtr);
            RSAWrapper.free_cstring(decryptPtr);
            return decrypt;
        }

        public string RsaEncrypt(string publicKey, string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(dataToEncrypt))
            {
                throw new Exception("You need to provide a public key and data to encrypt to use RsaEncrypt");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr encryptPtr = rsa_encrypt(publicKey, dataToEncrypt);
            string encrypt = Marshal.PtrToStringAnsi(encryptPtr);
            RSAWrapper.free_cstring(encryptPtr);
            return encrypt;
        }

        public RsaKeyPairResult GetKeyPair(int keySize)
        {
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new Exception("Please pass in a valid key size.");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            RustRsaKeyPairStruct keyPairStruct = get_key_pair(keySize);
            RsaKeyPairResult result = new RsaKeyPairResult()
            {
                PrivateKey = Marshal.PtrToStringAnsi(keyPairStruct.priv_key),
                PublicKey = Marshal.PtrToStringAnsi(keyPairStruct.pub_key)
            };
            RSAWrapper.free_cstring(keyPairStruct.pub_key);
            RSAWrapper.free_cstring(keyPairStruct.priv_key);
            return result;
        }
    }
}
