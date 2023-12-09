using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class SHAWrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;
        public SHAWrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [DllImport("performant_encryption.dll")]
        private static extern IntPtr sha512(string password);
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr sha256(string password);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public string SHA512HashString(string stringTohash)
        {
            if (string.IsNullOrEmpty(stringTohash))
            {
                throw new Exception("Please provide a string to hash");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr hashedPtr = sha512(stringTohash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            SHAWrapper.free_cstring(hashedPtr);
            return hashed;
        }
        public string SHA256HashString(string stringToHash)
        {
            if (string.IsNullOrEmpty(stringToHash))
            {
                throw new Exception("Please provide a string to hash");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr hashedPtr = sha256(stringToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            SHAWrapper.free_cstring(hashedPtr);
            return hashed;
        }
    }
}