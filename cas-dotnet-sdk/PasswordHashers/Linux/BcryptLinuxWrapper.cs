using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.PasswordHashers.Linux
{
    internal static class BcryptLinuxWrapper
    {
        [DllImport("performant_encryption.so")]
        public static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("performant_encryption.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool bcrypt_verify(string password, string hash);
        [DllImport("performant_encryption.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
