using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Windows;
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
                throw new NotImplementedException("Linux version not yet supported");
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
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                return BcryptWindowsWrapper.bcrypt_verify(unhashed, hashedPassword);
            }
        }
    }
}