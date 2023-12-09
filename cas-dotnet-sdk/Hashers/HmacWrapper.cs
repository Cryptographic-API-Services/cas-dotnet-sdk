using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class HmacWrapper
    {
        private readonly OSPlatform _platform;

        public HmacWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }
        public string HmacSign(string key, string message)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Please provide a key to sign with HMAC");
            }
            if (string.IsNullOrEmpty(message))
            {
                throw new Exception("Please provide a message to sign with HMAC");
            }

            if (this._platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr signedPtr = HmacWindowsWrapper.hmac_sign(key, message);
                string signed = Marshal.PtrToStringAnsi(signedPtr);
                HmacWindowsWrapper.free_cstring(signedPtr);
                return signed;
            }
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

            if (this._platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                return HmacWindowsWrapper.hmac_verify(key, message, signature);
            }
        }
    }
}