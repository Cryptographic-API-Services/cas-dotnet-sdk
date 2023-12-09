using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class Argon2LinuxWrappper
    {

        [DllImport("performant_encryption.so")]
        public static extern IntPtr argon2_hash(string passToHash);
        [DllImport("performant_encryption.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);
        [DllImport("performant_encryption.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
