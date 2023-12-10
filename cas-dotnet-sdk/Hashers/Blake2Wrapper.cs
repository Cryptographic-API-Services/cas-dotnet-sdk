using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class Blake2Wrapper
    {
        private readonly OSPlatform _platform;
        public Blake2Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public string Blake2512(string toHash)
        {
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("Please provide a string to hash with Blake2 512");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Blake2LinuxWrapper.blake2_512(toHash);
                string hashedString = Marshal.PtrToStringAnsi(hashedPtr);
                Blake2LinuxWrapper.free_cstring(hashedPtr);
                return hashedString;
            }
            else
            {
                IntPtr hashedPtr = Blake2WindowsWrapper.blake2_512(toHash);
                string hashedString = Marshal.PtrToStringAnsi(hashedPtr);
                Blake2WindowsWrapper.free_cstring(hashedPtr);
                return hashedString;
            }
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

            if (this._platform == OSPlatform.Linux)
            {
                return Blake2LinuxWrapper.blake2_512_verify(dataToVerify, hash);
            }
            else
            {
                return Blake2WindowsWrapper.blake2_512_verify(dataToVerify, hash);
            }
        }

        public string Blake2256(string toHash)
        {
            if (string.IsNullOrEmpty(toHash))
            {
                throw new Exception("Please provide a string to hash with Blake2 256");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Blake2LinuxWrapper.blake2_256(toHash);
                string hashedStr = Marshal.PtrToStringAnsi(hashedPtr);
                Blake2LinuxWrapper.free_cstring(hashedPtr);
                return hashedStr;
            }
            else
            {
                IntPtr hashedPtr = Blake2WindowsWrapper.blake2_256(toHash);
                string hashedStr = Marshal.PtrToStringAnsi(hashedPtr);
                Blake2WindowsWrapper.free_cstring(hashedPtr);
                return hashedStr;
            }
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

            if (this._platform == OSPlatform.Linux)
            {
                return Blake2LinuxWrapper.blake2_256_verify(dataToVerify, hash);
            }
            else
            {
                return Blake2WindowsWrapper.blake2_256_verify(dataToVerify, hash);
            }
        }
    }
}