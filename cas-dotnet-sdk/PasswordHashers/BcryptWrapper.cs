using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class BcryptWrapper
    {
        private readonly OSPlatform _platform;
        public BcryptWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public string HashPassword(string passwordToHash)
        {
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = BcryptLinuxWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                BcryptLinuxWrapper.free_cstring(hashedPtr);
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = BcryptWindowsWrapper.bcrypt_hash(passwordToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                BcryptWindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }
        public bool Verify(string hashedPassword, string unhashed)
        {
            if (this._platform == OSPlatform.Linux)
            {
                return BcryptLinuxWrapper.bcrypt_verify(unhashed, hashedPassword);
            }
            else
            {
                return BcryptWindowsWrapper.bcrypt_verify(unhashed, hashedPassword);
            }
        }
    }
}