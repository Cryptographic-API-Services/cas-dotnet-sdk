using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class SHAWrapper
    {
        private readonly OSPlatform _platform;
        public SHAWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public string SHA512HashString(string stringTohash)
        {
            if (string.IsNullOrEmpty(stringTohash))
            {
                throw new Exception("Please provide a string to hash");
            }

            if (this._platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr hashedPtr = SHAWindowsWrapper.sha512(stringTohash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHAWindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }
        public string SHA256HashString(string stringToHash)
        {
            if (string.IsNullOrEmpty(stringToHash))
            {
                throw new Exception("Please provide a string to hash");
            }

            if (this._platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr hashedPtr = SHAWindowsWrapper.sha256(stringToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHAWindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }
    }
}