using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.KeyExchange.Types
{
    public class X25519SecretPublicKey
    {
        public byte[] SecretKey { get; set; }
        public byte[] PublicKey { get; set; }
    }
}
