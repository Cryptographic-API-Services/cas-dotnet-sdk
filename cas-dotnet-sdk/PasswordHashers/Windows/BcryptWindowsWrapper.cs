using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class BcryptWindowsWrapper
    {
        [DllImport("performant_encryption.dll")]
        public static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool bcrypt_verify(string password, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
