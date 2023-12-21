using CasDotnetSdk.Hashers.Linux;
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

        internal struct SHAHashByteResult
        {
            public IntPtr result_bytes_ptr;
            public int length;
        }

        public string SHA512HashString(string stringTohash)
        {
            if (string.IsNullOrEmpty(stringTohash))
            {
                throw new Exception("Please provide a string to hash");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = SHALinuxWrapper.sha512(stringTohash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHALinuxWrapper.free_cstring(hashedPtr);
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = SHAWindowsWrapper.sha512(stringTohash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHAWindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }

        public byte[] SHA512HashBytes(byte[] dataToHash)
        {
            if (dataToHash == null)
            {
                throw new Exception("You must provide a byte array of data to hash");
            }
            if (dataToHash.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to hash");
            }
            if (this._platform == OSPlatform.Linux)
            {
                SHAHashByteResult hashedPtr = SHALinuxWrapper.sha512_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHALinuxWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                return result;
            }
            else
            {
                SHAHashByteResult hashedPtr = SHAWindowsWrapper.sha512_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHAWindowsWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                return result;
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
                IntPtr hashedPtr = SHALinuxWrapper.sha256(stringToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHALinuxWrapper.free_cstring(hashedPtr);
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = SHAWindowsWrapper.sha256(stringToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SHAWindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }

        public byte[] SHA256HashBytes(byte[] dataToHash)
        {
            if (dataToHash == null)
            {
                throw new Exception("You must provide a byte array of data to hash");
            }
            if (dataToHash.Length == 0)
            {
                throw new Exception("You must provide a byte array with allocated data to hash");
            }
            if (this._platform == OSPlatform.Linux)
            {
                SHAHashByteResult hashedPtr = SHALinuxWrapper.sha256_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHALinuxWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                return result;
            }
            else
            {
                SHAHashByteResult hashedPtr = SHAWindowsWrapper.sha256_bytes(dataToHash, dataToHash.Length);
                byte[] result = new byte[hashedPtr.length];
                Marshal.Copy(hashedPtr.result_bytes_ptr, result, 0, hashedPtr.length);
                SHAWindowsWrapper.free_bytes(hashedPtr.result_bytes_ptr);
                return result;
            }
        }
    }
}