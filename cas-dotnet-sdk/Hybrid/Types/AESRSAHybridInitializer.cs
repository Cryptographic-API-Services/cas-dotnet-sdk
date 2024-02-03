using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Symmetric;
using System;

namespace CasDotnetSdk.Hybrid.Types
{
    public class AESRSAHybridInitializer
    {
        public int AesType { get; set; }
        public string AesKey { get; set; }
        public string AesNonce { get; set; }
        public RsaKeyPairResult RsaKeyPair { get; set; }
        public AESRSAHybridInitializer(int aesType, int rsaSize) 
        {
            this.InitAes(aesType);
            this.InitRsaKeyPair(rsaSize);
        }

        private void InitAes(int aesType)
        {
            if (aesType != 128 && aesType != 256)
            {
                throw new Exception("You must provide a AES key size of 128 of 256 bits");
            }
            AESWrapper wrapper = new AESWrapper();
            this.AesType = aesType;
            this.AesKey = (aesType == 128) ? wrapper.Aes128Key() : wrapper.Aes256Key();
            this.AesNonce = wrapper.GenerateAESNonce();
        }

        private void InitRsaKeyPair(int rsaSize)
        {
            if (rsaSize != 1024 && rsaSize != 2048 && rsaSize != 4096)
            {
                throw new Exception("You must provide a valid rsa key size of 10248, 2048, 4096");
            }
            this.RsaKeyPair = new RSAWrapper().GetKeyPair(rsaSize);
        }
    }
}