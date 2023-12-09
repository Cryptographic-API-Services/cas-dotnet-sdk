using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class MD5Wrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;
        public MD5Wrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [DllImport("performant_encryption.dll")]
        private static extern IntPtr md5_hash_string(string toHash);
        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool md5_hash_verify(string hashToVerify, string toHash);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public string Hash(string toHash)
        {
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("You must provide data to hash the string");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr hashedPtr = md5_hash_string(toHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            MD5Wrapper.free_cstring(hashedPtr);
            return hashed;
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
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return md5_hash_verify(hashToVerify, toHash);
        }
    }
}
