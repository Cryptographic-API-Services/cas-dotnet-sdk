﻿using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class Argon2WindowsWrapper
    {

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr argon2_hash(string passToHash);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern IntPtr argon2_hash_threadpool(string passToHash);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify_threadpool(string hashedPassword, string passToVerify);

        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
