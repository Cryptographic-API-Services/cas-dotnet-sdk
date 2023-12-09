using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class Blake2Wrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;
        public Blake2Wrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [DllImport("performant_encryption.dll")]
        private static extern IntPtr blake2_512(string toHash);
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr blake2_256(string toHash);
        [DllImport("performant_encryption.dll")]
        public static extern bool blake2_256_verify(string dataToVerify, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern bool blake2_512_verify(string dataToVerify, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public string Blake2512(string toHash)
        {
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("Please provide a string to hash with Blake2 512");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr hashedPtr = blake2_512(toHash);
            string hashedString = Marshal.PtrToStringAnsi(hashedPtr);
            Blake2Wrapper.free_cstring(hashedPtr);
            return hashedString;
        }
        public bool Blake2512Verify(string dataToVerify, string hash)
        {
            if (string.IsNullOrEmpty(dataToVerify))
            {
                throw new Exception("Please provide data to verify with Blake2 512");
            }
            else if (string.IsNullOrEmpty(hash))
            {
                throw new Exception("Please provide a hash to verify with Blake2 512");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return blake2_512_verify(dataToVerify, hash);
        }

        public string Blake2256(string toHash)
        {
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("Please provide a string to hash with Blake2 256");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr hashedPtr = blake2_256(toHash);
            string hashedStr = Marshal.PtrToStringAnsi(hashedPtr);
            Blake2Wrapper.free_cstring(hashedPtr);
            return hashedStr;
        }

        public bool Blake2256Verify(string dataToVerify, string hash)
        {
            if (string.IsNullOrEmpty(dataToVerify))
            {
                throw new Exception("Please provide data to verify with Blake2 256");
            }
            else if (string.IsNullOrEmpty(hash))
            {
                throw new Exception("Please provide a hash to verify with Blake2 256");
            }
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return blake2_256_verify(dataToVerify, hash);
        }
    }
}