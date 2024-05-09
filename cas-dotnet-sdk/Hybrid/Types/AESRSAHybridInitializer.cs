using CasDotnetSdk.Symmetric;
using System;

namespace CasDotnetSdk.Hybrid.Types
{
    public class AESRSAHybridInitializer
    {
        public int AesType { get; set; }
        public int RsaType { get; set; }
        public string AesNonce { get; set; }
        public AESRSAHybridInitializer(int aesType, int rsaType)
        {
            if (aesType != 128 && aesType != 256)
            {
                throw new Exception("You must provide a AES key size of 128 of 256 bits");
            }
            else
            {
                this.AesType = aesType;
            }

            if (rsaType != 1024 && rsaType != 2048 && rsaType != 4096)
            {
                throw new Exception("You must provide a valid rsa key size of 10248, 2048, 4096");
            }
            else
            {
                this.RsaType = rsaType;
            }
            this.AesNonce = new AESWrapper().GenerateAESNonce();
        }
    }
}
