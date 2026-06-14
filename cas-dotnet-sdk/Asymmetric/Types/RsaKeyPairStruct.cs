using System;

namespace CasDotnetSdk.Asymmetric.Types
{
    internal struct RsaKeyPairStruct
    {
        public IntPtr pub_key;
        public IntPtr priv_key;
        public int error_code;
    }
}
