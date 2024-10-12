using CasDotnetSdk.Hybrid.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hybrid.Windows
{
    internal static class HpkeWindowsWrapper
    {
        [DllImport("\\Contents\\cas_core_lib.dll")]
        public static extern HpkeKeyPairResultStruct hpke_generate_keypair();
    }
}
