using System;

namespace CasDotnetSdk.Asymmetric.Types
{
    internal struct RsaSignResultStruct
    {
        public IntPtr signature;
        public IntPtr public_key;
    }
}
