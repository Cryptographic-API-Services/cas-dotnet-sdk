﻿using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class SCryptWrapper
    {
        private readonly OSPlatform _platform;
        public SCryptWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = SCryptLinuxWrapper.scrypt_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SCryptLinuxWrapper.free_cstring(hashedPtr);
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = SCryptWindowsWrapper.scrypt_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SCryptWindowsWrapper.free_cstring(hashedPtr);
                return hashed;
            }
        }

        public bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            {
                throw new Exception("Please provide a password and a hash to verify");
            }
            if (this._platform == OSPlatform.Linux)
            {
                return SCryptLinuxWrapper.scrypt_verify(password, hash);
            }
            else
            {
                return SCryptWindowsWrapper.scrypt_verify(password, hash);
            }
        }
    }
}