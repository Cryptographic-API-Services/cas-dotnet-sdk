using CasDotnetSdk.Sponges;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests
{
    public class AsconWrapperTests
    {
        private readonly AsconWrapper _asconWrapper;

        public AsconWrapperTests()
        {
            this._asconWrapper = new AsconWrapper();
        }

        [Fact]
        public void Ascon128Key()
        {
            string key = this._asconWrapper.Ascon128Key();
            Assert.True(!string.IsNullOrEmpty(key));
        }

        [Fact]
        public void Ascon128Nonce()
        {
            string nonce = this._asconWrapper.Ascon128Nonce();
            Assert.True(!string.IsNullOrEmpty(nonce));
        }

        [Fact]
        public void Ascon128Encrypt()
        {
            string key = this._asconWrapper.Ascon128Key();
            string nonce = this._asconWrapper.Ascon128Nonce();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ChattingOnTwitchAsIWorkOnThis");
            byte[] encrypted = this._asconWrapper.Ascon128Encrypt(nonce, key, dataToEncrypt);
            Assert.True(!dataToEncrypt.SequenceEqual(encrypted));
        }

        [Fact]
        public void Ascon128Decrypt()
        {
            string key = this._asconWrapper.Ascon128Key();
            string nonce = this._asconWrapper.Ascon128Nonce();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ChattingOnTwitchAsIWorkOnThis");
            byte[] encrypted = this._asconWrapper.Ascon128Encrypt(nonce, key, dataToEncrypt);
            byte[] decrypted = this._asconWrapper.Ascon128Decrypt(nonce, key, encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
        }
    }
}
