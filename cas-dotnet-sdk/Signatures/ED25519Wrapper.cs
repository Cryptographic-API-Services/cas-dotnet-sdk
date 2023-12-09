using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures
{
    public class ED25519Wrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;

        public ED25519Wrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        public class Ed25519SignatureResult
        {
            public string Signature { get; set; }
            public string PublicKey { get; set; }
        }

        private struct Ed25519SignatureStruct
        {
            public IntPtr Signature { get; set; }
            public IntPtr Public_Key { get; set; }
        }

        [DllImport("performant_encryption.dll")]
        private static extern IntPtr get_ed25519_key_pair();
        [DllImport("performant_encryption.dll")]
        private static extern Ed25519SignatureStruct sign_with_key_pair(string keyBytes, string dataToSign);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool verify_with_key_pair(string keyBytes, string signature, string dataToVerify);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool verify_with_public_key(string publicKey, string signature, string dataToVerify);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public string GetKeyPair()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr keyPairPtr = get_ed25519_key_pair();
            string keyPair = Marshal.PtrToStringAnsi(keyPairPtr);
            ED25519Wrapper.free_cstring(keyPairPtr);
            return keyPair;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            Ed25519SignatureStruct signatureStruct = sign_with_key_pair(keyBytes, dataToSign);
            Ed25519SignatureResult result = new Ed25519SignatureResult()
            {
                Signature = Marshal.PtrToStringAnsi(signatureStruct.Signature),
                PublicKey = Marshal.PtrToStringAnsi(signatureStruct.Public_Key)
            };
            ED25519Wrapper.free_cstring(signatureStruct.Signature);
            ED25519Wrapper.free_cstring(signatureStruct.Public_Key);
            return result;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return verify_with_key_pair(keyBytes, signature, dataToVerify);
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return verify_with_public_key(publicKey, signature, dataToVerify);
        }
    }
}