using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Signatures.Types
{
    internal struct Ed25519SignatureStruct
    {
        public IntPtr Signature { get; set; }
        public IntPtr Public_Key { get; set; }
    }
}
