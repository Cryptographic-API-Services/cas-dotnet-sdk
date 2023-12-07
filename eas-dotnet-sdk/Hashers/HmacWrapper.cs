using EasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace EasDotnetSdk
{
    public class HmacWrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;

        public HmacWrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [DllImport("performant_encryption.dll")]
        private static extern IntPtr hmac_sign(string key, string message);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool hmac_verify(string key, string message, string signature);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public IntPtr HmacSign(string key, string message)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Please provide a key to sign with HMAC");
            }
            if (string.IsNullOrEmpty(message))
            {
                throw new Exception("Please provide a message to sign with HMAC");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return hmac_sign(key, message);
        }
        public bool HmacVerify(string key, string message, string signature)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Please provide a key to verify with HMAC");
            }
            if (string.IsNullOrEmpty(message))
            {
                throw new Exception("Please provide a message to verify with HMAC");
            }
            if (string.IsNullOrEmpty(signature))
            {
                throw new Exception("Please provide a signature to verify with HMAC");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return hmac_verify(key, message, signature);
        }
    }
}