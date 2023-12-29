using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Windows;
using CASHelpers;
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

        internal struct Blake2HashByteResult
        {
            public IntPtr result_bytes_ptr;
            public int length;
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

        public byte[] Blake2512Bytes(byte[] toHash)
        {
            if (toHash == null || toHash.Length == 0)
            {
                throw new Exception("You must provide datat to hash with Blake 2 512");
            }
            if (this._platform == OSPlatform.Linux)
            {
                Blake2HashByteResult hashResult = Blake2LinuxWrapper.blake2_512_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashResult.length];
                Marshal.Copy(hashResult.result_bytes_ptr, result, 0, hashResult.length);
                Blake2LinuxWrapper.free_bytes(hashResult.result_bytes_ptr);
                return result;
            }
            else
            {
                Blake2HashByteResult hashResult = Blake2WindowsWrapper.blake2_512_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashResult.length];
                Marshal.Copy(hashResult.result_bytes_ptr, result, 0, hashResult.length);
                Blake2WindowsWrapper.free_bytes(hashResult.result_bytes_ptr);
                return result;
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

        public bool Blake2512VerifyBytes(byte[] hashedData, byte[] toCompare)
        {
            if (hashedData == null || hashedData.Length == 0)
            {
                throw new Exception("You must provide previously hashed data to verify with Blake 2 512");
            }
            if (toCompare == null || toCompare.Length == 0)
            {
                throw new Exception("You must provide data to compare to verify with Blake 2 512");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return Blake2LinuxWrapper.blake2_512_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
            }
            else
            {
                return Blake2WindowsWrapper.blake2_512_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
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
        public byte[] Blake2256Bytes(byte[] toHash)
        {
            if (toHash == null || toHash.Length == 0)
            {
                throw new Exception("You must provide an array of allocated data to hash with Blake2 256");
            }
            if (this._platform == OSPlatform.Linux)
            {
                Blake2HashByteResult hashedResult = Blake2LinuxWrapper.blake2_256_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashedResult.length];
                Marshal.Copy(hashedResult.result_bytes_ptr, result, 0, result.Length);
                Blake2LinuxWrapper.free_bytes(hashedResult.result_bytes_ptr);
                return result;
            }
            else
            {
                Blake2HashByteResult hashedResult = Blake2WindowsWrapper.blake2_256_bytes(toHash, toHash.Length);
                byte[] result = new byte[hashedResult.length];
                Marshal.Copy(hashedResult.result_bytes_ptr, result, 0, result.Length);
                Blake2WindowsWrapper.free_bytes(hashedResult.result_bytes_ptr);
                return result;
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

        public bool Blake2256BytesVerify(byte[] hashedData, byte[] toCompare)
        {
            if (hashedData == null || hashedData.Length == 0)
            {
                throw new Exception("You must provide allocated data for the previously hashed data to compare with Blake 2 256");
            }
            if (toCompare == null || toCompare.Length == 0)
            {
                throw new Exception("You must provide allocated data for the data to compare with Blake 2 256");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return Blake2LinuxWrapper.blake2_256_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
            }
            else
            {
                return Blake2WindowsWrapper.blake2_256_bytes_verify(hashedData, hashedData.Length, toCompare, toCompare.Length);
            }
        }
    }
}