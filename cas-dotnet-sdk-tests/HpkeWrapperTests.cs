using CasDotnetSdk.Hybrid;
using CasDotnetSdk.Hybrid.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests
{
    public class HpkeWrapperTests
    {
        private HpkeWrapper _wrapper { get; set; }

        public HpkeWrapperTests()
        {
            this._wrapper = new HpkeWrapper();
        }

        [Fact]
        public void GenerateKeyPair()
        {
            HpkeKeyPairResult result = this._wrapper.GenerateKeyPair();
            Assert.NotNull(result.PublicKey);
            Assert.NotNull(result.PrivateKey);
            Assert.NotEmpty(result.InfoStr);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.PrivateKey);
            Assert.NotEmpty(result.InfoStr);
        }

        [Fact] 
        public void Encrypt()
        {
            HpkeKeyPairResult keyPair = this._wrapper.GenerateKeyPair();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("EncryptThisDataString");
            HpkeEncryptResult result = this._wrapper.Encrypt(dataToEncrypt, keyPair.PublicKey, keyPair.InfoStr);
            Assert.NotNull(result.EncappedKey);
            Assert.NotNull(result.Ciphertext);
            Assert.NotNull(result.Tag);
            Assert.NotEmpty(result.EncappedKey);
            Assert.NotEmpty(result.Ciphertext);
            Assert.NotEmpty(result.Tag);
        }
    }
}
