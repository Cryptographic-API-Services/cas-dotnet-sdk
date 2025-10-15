using CasDotnetSdk.PQC.Types;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PQC.Linux
{
    public class SLHDSALinuxWrapper
    {
        [DllImport("libcas_core_lib.so")]
        public static extern SLHDSAKeyPairStruct slh_dsa_generate_signing_and_verification_key();
    }
}
