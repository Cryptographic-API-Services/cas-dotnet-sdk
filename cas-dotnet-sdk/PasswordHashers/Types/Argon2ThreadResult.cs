using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.PasswordHashers.Types
{
    internal struct Argon2ThreadResult
    {
        public IntPtr passwords { get; set; }
        public int length { get; set; }
    }
}
