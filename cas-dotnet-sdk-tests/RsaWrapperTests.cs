using System;
using System.Security.Cryptography;
using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Asymmetric.Types;
using CasDotnetSdk.Helpers;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class RSAWrapperTests
    {
        private readonly RSAWrapper _RSAWrapper;
        private readonly RsaKeyPairResult _encryptDecryptKeyPair;
        public RSAWrapperTests()
        {
            this._RSAWrapper = new RSAWrapper();
            this._encryptDecryptKeyPair = this._RSAWrapper.GetKeyPair(4096);
        }

        [Fact]
        public void CreateKeyPair()
        {
            RsaKeyPairResult keyPair = this._RSAWrapper.GetKeyPair(4096);
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);
        }

        [Fact]
        public async Task RsaSignBytes()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(4096);
            byte[] signature = this._RSAWrapper.Sign(keys.PrivateKey, dataToSign);
            Assert.NotEqual(dataToSign, signature);
        }


        [Fact]
        public async Task RsaVerifyBytes()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("Sign This Data For RSA");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(4096);
            byte[] signature = this._RSAWrapper.Sign(keys.PrivateKey, dataToSign);
            bool isValid = this._RSAWrapper.Verify(keys.PublicKey, dataToSign, signature);
            Assert.True(isValid);
        }


        [Theory]
        [InlineData(1024)]
        [InlineData(1536)]
        [InlineData(8192)]
        public void GetKeyPairRejectsUnsupportedSizes(int keySize)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => this._RSAWrapper.GetKeyPair(keySize));
        }

        [Fact]
        public void GetKeyPair3072()
        {
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(3072);
            byte[] data = Encoding.UTF8.GetBytes("3072-bit keys are supported");
            Assert.True(this._RSAWrapper.Verify(keys.PublicKey, data, this._RSAWrapper.Sign(keys.PrivateKey, data)));
        }

        [Fact]
        public void SignatureIsStandardRs256()
        {
            // Sign is RSASSA-PKCS1-v1_5 with SHA-256 over the message (#214), so .NET's own
            // RSA verifies it, and the SDK verifies a signature .NET made.
            byte[] data = Encoding.UTF8.GetBytes("Interoperable RS256 signature");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(2048);
            byte[] signature = this._RSAWrapper.Sign(keys.PrivateKey, data);

            using RSA dotnetRsa = RSA.Create();
            dotnetRsa.ImportFromPem(keys.PublicKey);
            Assert.True(dotnetRsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

            using RSA dotnetSigner = RSA.Create();
            dotnetSigner.ImportFromPem(keys.PrivateKey);
            byte[] dotnetSignature = dotnetSigner.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(this._RSAWrapper.Verify(keys.PublicKey, data, dotnetSignature));
        }

        [Fact]
        public void VerifyRejectsTamperedMessage()
        {
            byte[] data = Encoding.UTF8.GetBytes("Original message");
            byte[] signature = this._RSAWrapper.Sign(this._encryptDecryptKeyPair.PrivateKey, data);
            Assert.False(this._RSAWrapper.Verify(this._encryptDecryptKeyPair.PublicKey, Encoding.UTF8.GetBytes("Tampered message"), signature));
        }

        [Fact]
        public void SignPssVerifyPss()
        {
            byte[] data = Encoding.UTF8.GetBytes("Sign This Data With RSA-PSS");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(2048);
            byte[] signature = this._RSAWrapper.SignPss(keys.PrivateKey, data);
            Assert.Equal(256, signature.Length);
            Assert.True(this._RSAWrapper.VerifyPss(keys.PublicKey, data, signature));

            // PSS uses a random salt, so a second signature differs but also verifies.
            byte[] second = this._RSAWrapper.SignPss(keys.PrivateKey, data);
            Assert.NotEqual(signature, second);
            Assert.True(this._RSAWrapper.VerifyPss(keys.PublicKey, data, second));
        }

        [Fact]
        public void VerifyPssRejectsTamperedMessage()
        {
            byte[] data = Encoding.UTF8.GetBytes("Original message");
            byte[] signature = this._RSAWrapper.SignPss(this._encryptDecryptKeyPair.PrivateKey, data);
            Assert.False(this._RSAWrapper.VerifyPss(this._encryptDecryptKeyPair.PublicKey, Encoding.UTF8.GetBytes("Tampered message"), signature));
        }

        [Fact]
        public void VerifyPssRejectsTamperedSignature()
        {
            byte[] data = Encoding.UTF8.GetBytes("Original message");
            byte[] signature = this._RSAWrapper.SignPss(this._encryptDecryptKeyPair.PrivateKey, data);
            signature[signature.Length / 2] ^= 0x01;
            Assert.False(this._RSAWrapper.VerifyPss(this._encryptDecryptKeyPair.PublicKey, data, signature));
        }

        [Fact]
        public void PssAndPkcs1SignaturesAreNotInterchangeable()
        {
            byte[] data = Encoding.UTF8.GetBytes("Padding schemes must not be confused");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(2048);
            Assert.False(this._RSAWrapper.Verify(keys.PublicKey, data, this._RSAWrapper.SignPss(keys.PrivateKey, data)));
            Assert.False(this._RSAWrapper.VerifyPss(keys.PublicKey, data, this._RSAWrapper.Sign(keys.PrivateKey, data)));
        }

        [Fact]
        public void PssSignatureIsStandardPs256()
        {
            // SignPss is RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt (#214). .NET's
            // RSASignaturePadding.Pss uses a salt as long as the hash, so the two interoperate both ways.
            byte[] data = Encoding.UTF8.GetBytes("Interoperable PS256 signature");
            RsaKeyPairResult keys = this._RSAWrapper.GetKeyPair(2048);
            byte[] signature = this._RSAWrapper.SignPss(keys.PrivateKey, data);

            using RSA dotnetRsa = RSA.Create();
            dotnetRsa.ImportFromPem(keys.PublicKey);
            Assert.True(dotnetRsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

            using RSA dotnetSigner = RSA.Create();
            dotnetSigner.ImportFromPem(keys.PrivateKey);
            byte[] dotnetSignature = dotnetSigner.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Assert.True(this._RSAWrapper.VerifyPss(keys.PublicKey, data, dotnetSignature));
            Assert.False(this._RSAWrapper.VerifyPss(keys.PublicKey, Encoding.UTF8.GetBytes("Other message"), dotnetSignature));
        }

        [Fact]
        public void PssRejectsInvalidArguments()
        {
            byte[] data = Encoding.UTF8.GetBytes("data");
            Assert.Throws<ArgumentNullException>(() => this._RSAWrapper.SignPss(null!, data));
            Assert.Throws<ArgumentNullException>(() => this._RSAWrapper.SignPss(this._encryptDecryptKeyPair.PrivateKey, null!));
            Assert.Throws<ArgumentException>(() => this._RSAWrapper.SignPss(this._encryptDecryptKeyPair.PrivateKey, Array.Empty<byte>()));
            Assert.Throws<ArgumentNullException>(() => this._RSAWrapper.VerifyPss(null!, data, new byte[] { 1 }));
            Assert.Throws<ArgumentException>(() => this._RSAWrapper.VerifyPss(this._encryptDecryptKeyPair.PublicKey, data, Array.Empty<byte>()));
            Assert.Throws<CasException>(() => this._RSAWrapper.SignPss("not a PEM key", data));
        }
    }
}
