using CasDotnetSdk.Helpers;
using CasDotnetSdk.PasswordHashers.Linux;
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

        public string HashPasswordThread(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Argon2LinuxWrappper.argon2_hash_thread(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2LinuxWrappper.free_cstring(hashedPtr);
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = Argon2WindowsWrappper.argon2_hash_thread(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2WindowsWrappper.free_cstring(hashedPtr);
                return hashed;
            }
        }

        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("You must provide a password to hash using argon2");
            }

            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = Argon2LinuxWrappper.argon2_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                Argon2LinuxWrappper.free_cstring(hashedPtr);
                return hashed;
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
                return Argon2LinuxWrappper.argon2_verify(hashedPasswrod, password);
            }
            else
            {
                return Argon2WindowsWrappper.argon2_verify(hashedPasswrod, password);
            }
        }

        public bool VerifyPasswordThread(string hashedPasswrod, string password)
        {
            if (string.IsNullOrEmpty(hashedPasswrod) || string.IsNullOrEmpty(password))
            {
                throw new Exception("You must provide a hashed password and password to verify with argon2");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return Argon2LinuxWrappper.argon2_verify_thread(hashedPasswrod, password);
            }
            else
            {
                return Argon2WindowsWrappper.argon2_verify_thread(hashedPasswrod, password);
            }
        }
    }
}
