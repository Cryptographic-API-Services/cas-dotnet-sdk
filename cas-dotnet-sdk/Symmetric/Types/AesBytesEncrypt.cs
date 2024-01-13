using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Symmetric.Types
{
    internal struct AesBytesEncrypt
    {
        public IntPtr ciphertext { get; set; }
        public int length { get; set; }
    }
}
