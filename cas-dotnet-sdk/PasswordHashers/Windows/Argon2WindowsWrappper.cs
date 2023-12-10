using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.PasswordHashers.Windows
{
    internal static class Argon2WindowsWrappper
    {

        [DllImport("cas_core_lib.dll")]
        public static extern IntPtr argon2_hash(string passToHash);
        [DllImport("cas_core_lib.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool argon2_verify(string hashedPassword, string passToVerify);
        [DllImport("cas_core_lib.dll")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
