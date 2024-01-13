using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519KeyPairBytesResultStruct
    {
        public IntPtr key_pair { get; set; }
        public int length { get; set; }
    }
}
