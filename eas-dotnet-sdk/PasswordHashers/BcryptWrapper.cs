using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace EasDotnetSdk.PasswordHash
{
    public class BcryptWrapper
    {
        [DllImport("performant_encryption.dll")]
        private static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool bcrypt_verify(string password, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public IntPtr HashPassword(string passwordToHash)
        {
            return bcrypt_hash(passwordToHash);
        }
        public bool Verify(string hashedPassword, string unhashed)
        {
            return bcrypt_verify(unhashed, hashedPassword);
        }
    }
}