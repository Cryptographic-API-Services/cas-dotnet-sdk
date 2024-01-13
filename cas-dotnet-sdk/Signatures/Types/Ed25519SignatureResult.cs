using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Signatures.Types
{
    public class Ed25519SignatureResult
    {
        public string Signature { get; set; }
        public string PublicKey { get; set; }
    }
}
