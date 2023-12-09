using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class Argon2Wrappper
    {
        private readonly OSPlatform _platform;

        public Argon2Wrappper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }

            if (this._platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr hashedPtr = Argon2WindowsWrappper.argon2_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2WindowsWrappper.free_cstring(hashedPtr);
                return hashed;
            }
        }
        public bool VerifyPassword(string hashedPasswrod, string password)
        {
            if (string.IsNullOrEmpty(hashedPasswrod) || string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }

            if (this._platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                return Argon2WindowsWrappper.argon2_verify(hashedPasswrod, password);
            }
        }
    }
}
