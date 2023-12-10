using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class MD5Wrapper
    {
        private readonly OSPlatform _platform;
        public MD5Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public string Hash(string toHash)
        {
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("You must provide data to hash the string");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = MD5LinuxWrapper.md5_hash_string(toHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                MD5LinuxWrapper.free_cstring(hashedPtr);
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = MD5WindowsWrapper.md5_hash_string(toHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                MD5WindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }

        public bool Verify(string hashToVerify, string toHash)
        {
            if (string.IsNullOrEmpty(hashToVerify))
            {
                throw new Exception("You must a hash to verify");
            }
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("You must provide a string to hash to verify");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return MD5LinuxWrapper.md5_hash_verify(hashToVerify, toHash);
            }
            else
            {
                return MD5WindowsWrapper.md5_hash_verify(hashToVerify, toHash);
            }
        }
    }
}
