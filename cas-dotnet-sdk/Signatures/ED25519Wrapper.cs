using CasDotnetSdk.Helpers;
using CasDotnetSdk.Signatures.Linux;
using CasDotnetSdk.Signatures.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures
{
    public class ED25519Wrapper
    {
        private readonly OSPlatform _platform;

        public ED25519Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public class Ed25519SignatureResult
        {
            public string Signature { get; set; }
            public string PublicKey { get; set; }
        }

        internal struct Ed25519SignatureStruct
        {
            public IntPtr Signature { get; set; }
            public IntPtr Public_Key { get; set; }
        }

        public string GetKeyPair()
        {
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr keyPairPtr = ED25519LinuxWrapper.get_ed25519_key_pair();
                string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
                ED25519LinuxWrapper.free_cstring(keyPairPtr);
                return keyPair;
            }
            else
            {
                IntPtr keyPairPtr = ED25519WindowsWrapper.get_ed25519_key_pair();
                string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
                ED25519WindowsWrapper.free_cstring(keyPairPtr);
                return keyPair;
            }
        }
        public Ed25519SignatureResult Sign(string keyBytes, string dataToSign)
        {
            if (string.IsNullOrEmpty(keyBytes))
            {
                throw new Exception("You need pass in the key bytes to sign data");
            }
            if (string.IsNullOrEmpty(dataToSign))
            {
                throw new Exception("You need to pass in data to sign, to sign data");
            }

            if (this._platform == OSPlatform.Linux)
            {
                Ed25519SignatureStruct signatureStruct = ED25519LinuxWrapper.sign_with_key_pair(keyBytes, dataToSign);
                Ed25519SignatureResult result = new Ed25519SignatureResult()
                {
                    Signature = Marshal.PtrToStringAnsi(signatureStruct.Signature),
                    PublicKey = Marshal.PtrToStringAnsi(signatureStruct.Public_Key)
                };
                ED25519LinuxWrapper.free_cstring(signatureStruct.Signature);
                ED25519LinuxWrapper.free_cstring(signatureStruct.Public_Key);
                return result;
            }
            else
            {
                Ed25519SignatureStruct signatureStruct = ED25519WindowsWrapper.sign_with_key_pair(keyBytes, dataToSign);
                Ed25519SignatureResult result = new Ed25519SignatureResult()
                {
                    Signature = Marshal.PtrToStringAnsi(signatureStruct.Signature),
                    PublicKey = Marshal.PtrToStringAnsi(signatureStruct.Public_Key)
                };
                ED25519WindowsWrapper.free_cstring(signatureStruct.Signature);
                ED25519WindowsWrapper.free_cstring(signatureStruct.Public_Key);
                return result;
            }
        }

        public bool Verify(string keyBytes, string signature, string dataToVerify)
        {
            if (string.IsNullOrEmpty(keyBytes))
            {
                throw new Exception("You need pass in the key bytes to verify data");
            }
            if (string.IsNullOrEmpty(signature))
            {
                throw new Exception("You need to pass in the signature to verify data");
            }
            if (string.IsNullOrEmpty(dataToVerify))
            {
                throw new Exception("You need to pass in data to verify, to verify data");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return ED25519LinuxWrapper.verify_with_key_pair(keyBytes, signature, dataToVerify);
            }
            else
            {
                return ED25519WindowsWrapper.verify_with_key_pair(keyBytes, signature, dataToVerify);
            }
        }
        public bool VerifyWithPublicKey(string publicKey, string signature, string dataToVerify)
        {
            if (string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("You need pass in the key bytes to verify data");
            }
            if (string.IsNullOrEmpty(signature))
            {
                throw new Exception("You need to pass in the signature to verify data");
            }
            if (string.IsNullOrEmpty(dataToVerify))
            {
                throw new Exception("You need to pass in data to verify, to verify data");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return ED25519LinuxWrapper.verify_with_public_key(publicKey, signature, dataToVerify);
            }
            else
            {
                return ED25519WindowsWrapper.verify_with_public_key(publicKey, signature, dataToVerify);
            }
        }
    }
}