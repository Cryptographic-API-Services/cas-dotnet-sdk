using System;

namespace CasDotnetSdk.PasswordHashers.Types
{
    internal struct Argon2KDFResult
    {
        public IntPtr key { get; set; }
        public long length { get; set; }
        public int error_code { get; set; }
    }
}
