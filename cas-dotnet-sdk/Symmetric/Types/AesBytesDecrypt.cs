using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Symmetric.Types
{
    internal struct AesBytesDecrypt
    {
        public IntPtr plaintext { get; set; }
        public int length { get; set; }
    }
}
