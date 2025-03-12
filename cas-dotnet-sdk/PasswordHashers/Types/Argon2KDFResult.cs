using System;

namespace CasDotnetSdk.PasswordHashers.Types
{
    internal struct Argon2KDFResult
    {
        public IntPtr key { get; set; }
        public int length { get; set; }
    }
}
