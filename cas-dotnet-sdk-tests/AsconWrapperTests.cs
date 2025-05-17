using System.Text;
using CasDotnetSdk.Sponges;
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
            byte[] key = this._asconWrapper.Ascon128Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Ascon128KeyThreadpool()
        {
            byte[] key = this._asconWrapper.Ascon128KeyThreadpool();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Ascon128Nonce()
        {
            byte[] nonce = this._asconWrapper.Ascon128Nonce();
            Assert.NotEmpty(nonce);
        }

        [Fact]
        public void Ascon128NonceThreadpool()
        {
            byte[] nonce = this._asconWrapper.Ascon128NonceThreadpool();
            Assert.NotEmpty(nonce);
        }

        [Fact]
        public void Ascon128Encrypt()
        {
            byte[] key = this._asconWrapper.Ascon128Key();
            byte[] nonce = this._asconWrapper.Ascon128Nonce();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ChattingOnTwitchAsIWorkOnThis");
            byte[] encrypted = this._asconWrapper.Ascon128Encrypt(nonce, key, dataToEncrypt);
            Assert.True(!dataToEncrypt.SequenceEqual(encrypted));
        }


        [Fact]
        public void Ascon128EncryptThreadpool()
        {
            byte[] key = this._asconWrapper.Ascon128KeyThreadpool();
            byte[] nonce = this._asconWrapper.Ascon128NonceThreadpool();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ChattingOnTwitchAsIWorkOnThis");
            byte[] encrypted = this._asconWrapper.Ascon128EncryptThreadpool(nonce, key, dataToEncrypt);
            Assert.True(!dataToEncrypt.SequenceEqual(encrypted));
        }

        [Fact]
        public void Ascon128Decrypt()
        {
            byte[] key = this._asconWrapper.Ascon128Key();
            byte[] nonce = this._asconWrapper.Ascon128Nonce();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ChattingOnTwitchAsIWorkOnThis");
            byte[] encrypted = this._asconWrapper.Ascon128Encrypt(nonce, key, dataToEncrypt);
            byte[] decrypted = this._asconWrapper.Ascon128Decrypt(nonce, key, encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
        }

        [Fact]
        public void Ascon128DecryptThreadpool()
        {
            byte[] key = this._asconWrapper.Ascon128KeyThreadpool();
            byte[] nonce = this._asconWrapper.Ascon128NonceThreadpool();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ChattingOnTwitchAsIWorkOnThis");
            byte[] encrypted = this._asconWrapper.Ascon128EncryptThreadpool(nonce, key, dataToEncrypt);
            byte[] decrypted = this._asconWrapper.Ascon128DecryptThreadpool(nonce, key, encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
        }
    }
}
