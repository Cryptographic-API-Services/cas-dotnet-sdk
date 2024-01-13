using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Signatures.Types
{
    public class Ed25519ByteSignatureResult
    {
        public byte[] Signature { get; set; }
        public byte[] PublicKey { get; set; }
    }
}
