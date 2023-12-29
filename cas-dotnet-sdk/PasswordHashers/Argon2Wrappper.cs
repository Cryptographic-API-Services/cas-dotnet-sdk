using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class Argon2Wrappper
    {
        private readonly OSPlatform _platform;

        internal struct Argon2ThreadResult
        {
            public IntPtr passwords { get; set; }
            public int length { get; set; }
        }

        public Argon2Wrappper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public string[] HashPasswordsThread(string[] passwordsToHash)
        {
            if (passwordsToHash == null || passwordsToHash.Length <= 0)
            {
                throw new Exception("You must provide a list of passwords to hash using argon2");
            }

            List<string> result = new List<string>();
            if (this._platform == OSPlatform.Linux)
            {
                Argon2ThreadResult hashedPasswordPtr = Argon2LinuxWrappper.argon2_hash_thread(passwordsToHash, passwordsToHash.Length);
                nint[] hashedResult = new nint[hashedPasswordPtr.length];
                Marshal.Copy(hashedPasswordPtr.passwords, hashedResult, 0, hashedPasswordPtr.length);
                for (int i = 0; i < hashedResult.Length; i++)
                {
                    string currentString = Marshal.PtrToStringAnsi(hashedResult[i]);
                    result.Add(currentString);
                    Argon2LinuxWrappper.free_cstring(hashedResult[i]);
                }
            }
            else
            {
                Argon2ThreadResult hashedPasswordPtr = Argon2WindowsWrappper.argon2_hash_thread(passwordsToHash, passwordsToHash.Length);
                nint[] hashedResult = new nint[hashedPasswordPtr.length];
                Marshal.Copy(hashedPasswordPtr.passwords, hashedResult, 0, hashedPasswordPtr.length);
                for (int i = 0; i < hashedResult.Length; i++)
                {
                    string currentString = Marshal.PtrToStringAnsi(hashedResult[i]);
                    result.Add(currentString);
                    Argon2WindowsWrappper.free_cstring(hashedResult[i]);
                }
            }
            return result.ToArray();
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
