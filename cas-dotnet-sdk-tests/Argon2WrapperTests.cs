using CasDotnetSdk.PasswordHashers;
using CasDotnetSdk.Symmetric;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class Argon2WrapperTests
    {
        private Argon2Wrapper _argon2Wrapper;
        private AESWrapper _aesWrapper;

        public Argon2WrapperTests()
        {
            this._argon2Wrapper = new Argon2Wrapper();
            this._aesWrapper = new AESWrapper();
        }

        [Fact]
        public void HashPasswordParameters()
        {
            string password = "ParameterTestPass@123";
            int memoryCost = 64;
            int iterations = 3;
            int parallelism = 4;
            string hash = this._argon2Wrapper.HashPasswordWithParameters(memoryCost, iterations, parallelism, password);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void HashPasswordParametersVerify()
        {
            string password = "ParamVerifyPass@456";
            int memoryCost = 500;
            int iterations = 4;
            int parallelism = 2;
            string hash = this._argon2Wrapper.HashPasswordWithParameters(memoryCost, iterations, parallelism, password);
            bool isValid = this._argon2Wrapper.Verify(hash, password);
            Assert.True(isValid);
        }

        [Theory]
        [InlineData(19, 1, 1)]
        [InlineData(19, 10, 1)]
        [InlineData(19, 1, 16)]
        public void HashPasswordParametersAcceptsBounds(int memoryCost, int iterations, int parallelism)
        {
            string password = "BoundsPassword!";
            string hash = this._argon2Wrapper.HashPasswordWithParameters(memoryCost, iterations, parallelism, password);
            Assert.Contains($"m={memoryCost * 1024},t={iterations},p={parallelism}", hash);
            Assert.True(this._argon2Wrapper.Verify(hash, password));
        }

        [Fact]
        public void HashPasswordParametersAcceptsMaxMemoryCost()
        {
            // Hashing at 4096 MiB would allocate 4 GiB in CI. The cost parameters are checked before the
            // password, so a null password shows that 4096 passes the range check.
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.HashPasswordWithParameters(Argon2Wrapper.MaxMemoryCostMiB, Argon2Wrapper.MaxIterations, Argon2Wrapper.MaxParallelism, null!));
        }

        [Theory]
        [InlineData(18, 2, 1, "memoryCost")]
        [InlineData(4097, 2, 1, "memoryCost")]
        [InlineData(4_194_305, 2, 1, "memoryCost")]
        [InlineData(-1, 2, 1, "memoryCost")]
        [InlineData(int.MinValue, 2, 1, "memoryCost")]
        [InlineData(19, 0, 1, "iterations")]
        [InlineData(19, 11, 1, "iterations")]
        [InlineData(19, -1, 1, "iterations")]
        [InlineData(19, 2, 0, "parallelism")]
        [InlineData(19, 2, 17, "parallelism")]
        [InlineData(19, 2, -1, "parallelism")]
        public void HashPasswordParametersRejectsOutOfRange(int memoryCost, int iterations, int parallelism, string paramName)
        {
            ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => this._argon2Wrapper.HashPasswordWithParameters(memoryCost, iterations, parallelism, "BoundsPassword!"));
            Assert.Equal(paramName, ex.ParamName);
        }

        [Fact]
        public void HashPassword()
        {
            string password = "DoNotUSETHISPASS@!";
            string hash = this._argon2Wrapper.HashPassword(password);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void Verify()
        {
            string password = "TestPasswordToVerify";
            string hash = this._argon2Wrapper.HashPassword(password);
            bool isValid = this._argon2Wrapper.Verify(hash, password);
            Assert.True(isValid);
        }

        [Fact]
        public void EmbeddedNulIsHashed()
        {
            string hashWithNul = this._argon2Wrapper.HashPassword("abc\0x");
            string hashWithoutNul = this._argon2Wrapper.HashPassword("abc");
            Assert.True(this._argon2Wrapper.Verify(hashWithNul, "abc\0x"));
            Assert.False(this._argon2Wrapper.Verify(hashWithNul, "abc"));
            Assert.False(this._argon2Wrapper.Verify(hashWithoutNul, "abc\0x"));
        }

        [Fact]
        public void RejectsNullOrEmptyPassword()
        {
            string hash = this._argon2Wrapper.HashPasswordWithParameters(19, 1, 1, "password");
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.HashPassword(null!));
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.HashPassword(""));
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.HashPasswordWithParameters(19, 1, 1, null!));
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.HashPasswordWithParameters(19, 1, 1, ""));
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.Verify(hash, null!));
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.Verify(hash, ""));
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.Verify(null!, "password"));
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.Verify("", "password"));
        }

        [Fact]
        public void RejectsUnpairedSurrogate()
        {
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.HashPassword("abc\uD800"));
        }

        [Fact]
        public void FactoryTest()
        {
            IPasswordHasherBase wrapper = PasswordHasherFactory.Get(PasswordHasherType.Argon2);
            string badPassword = "Don't DO It";
            string hahed = wrapper.HashPassword(badPassword);
            Assert.NotNull(wrapper);
            Assert.NotEqual(badPassword, hahed);
            Assert.Equal(typeof(Argon2Wrapper), wrapper.GetType());
            Assert.True(wrapper.Verify(hahed, badPassword));
        }

        [Fact]
        public void GenerateSalt()
        {
            byte[] first = this._argon2Wrapper.GenerateSalt();
            byte[] second = this._argon2Wrapper.GenerateSalt();
            Assert.Equal(Argon2Wrapper.MinSaltLength, first.Length);
            Assert.Equal(Argon2Wrapper.MinSaltLength, second.Length);
            Assert.False(first.SequenceEqual(second));
        }

        [Fact]
        public void DeriveAES128KeyWithSalt()
        {
            string password = "kdfsAreFun";
            byte[] salt = this._argon2Wrapper.GenerateSalt();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("LetsEncryptThisWord");
            byte[] key = this._argon2Wrapper.DeriveAES128Key(password, salt);
            byte[] aesNonce = this._aesWrapper.GenerateAESNonce();
            byte[] encrypted = this._aesWrapper.Aes128Encrypt(aesNonce, key, dataToEncrypt);

            byte[] rederived = this._argon2Wrapper.DeriveAES128Key(password, salt);
            byte[] decrypted = this._aesWrapper.Aes128Decrypt(aesNonce, rederived, encrypted);
            Assert.Equal(16, key.Length);
            Assert.Equal(key, rederived);
            Assert.Equal(dataToEncrypt, decrypted);
            Assert.NotEqual(key, this._argon2Wrapper.DeriveAES128Key(password, this._argon2Wrapper.GenerateSalt()));
            Assert.NotEqual(key, this._argon2Wrapper.DeriveAES128Key("kdfsAreFun!", salt));
        }

        [Fact]
        public void DeriveAES256KeyWithSalt()
        {
            string password = "kdfsAreFun";
            byte[] salt = this._argon2Wrapper.GenerateSalt();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("LetsEncrypt345343455ThisWor456d");
            byte[] key = this._argon2Wrapper.DeriveAES256Key(password, salt);
            byte[] aesNonce = this._aesWrapper.GenerateAESNonce();
            byte[] encrypted = this._aesWrapper.Aes256Encrypt(aesNonce, key, dataToEncrypt);

            byte[] rederived = this._argon2Wrapper.DeriveAES256Key(password, salt);
            byte[] decrypted = this._aesWrapper.Aes256Decrypt(aesNonce, rederived, encrypted);
            Assert.Equal(32, key.Length);
            Assert.Equal(key, rederived);
            Assert.Equal(dataToEncrypt, decrypted);
            Assert.NotEqual(key, this._argon2Wrapper.DeriveAES256Key(password, this._argon2Wrapper.GenerateSalt()));
            Assert.NotEqual(key, this._argon2Wrapper.DeriveAES256Key("kdfsAreFun!", salt));
        }

        [Fact]
        public void DeriveKeyWithSaltHashesEmbeddedNul()
        {
            byte[] salt = this._argon2Wrapper.GenerateSalt();
            Assert.NotEqual(this._argon2Wrapper.DeriveAES256Key("abc", salt), this._argon2Wrapper.DeriveAES256Key("abc\0x", salt));
        }

        [Fact]
        public void DeriveKeyWithSaltRejectsBadInput()
        {
            byte[] salt = this._argon2Wrapper.GenerateSalt();
            byte[] shortSalt = new byte[Argon2Wrapper.MinSaltLength - 1];
            foreach (Func<string, byte[], byte[]> derive in new Func<string, byte[], byte[]>[] { this._argon2Wrapper.DeriveAES256Key, this._argon2Wrapper.DeriveAES128Key })
            {
                Assert.Throws<ArgumentException>(() => derive("password", shortSalt));
                Assert.Throws<ArgumentException>(() => derive("password", Array.Empty<byte>()));
                Assert.Throws<ArgumentNullException>(() => derive("password", null!));
                Assert.Throws<ArgumentNullException>(() => derive(null!, salt));
                Assert.Throws<ArgumentException>(() => derive("", salt));
            }
        }

#pragma warning disable CS0618 // The random-salt overloads are obsolete; keep them working until they are removed.
        [Fact]
        public void DeriveAES128Key()
        {
            string password = "kdfsAreFun";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("LetsEncryptThisWord");
            byte[] key = this._argon2Wrapper.DeriveAES128Key(password);
            byte[] aesNonce = this._aesWrapper.GenerateAESNonce();
            byte[] encrypted = this._aesWrapper.Aes128Encrypt(aesNonce, key, dataToEncrypt);
            byte[] decrypted = this._aesWrapper.Aes128Decrypt(aesNonce, key, encrypted);
            Assert.Equal(16, key.Length);
            Assert.NotNull(encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.DeriveAES128Key(null!));
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.DeriveAES128Key(""));
        }

        [Fact]
        public void DeriveAES256Key()
        {
            string password = "kdfsAreFun";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("LetsEncrypt345343455ThisWor456d");
            byte[] key = this._argon2Wrapper.DeriveAES256Key(password);
            byte[] aesNonce = this._aesWrapper.GenerateAESNonce();
            byte[] encrypted = this._aesWrapper.Aes256Encrypt(aesNonce, key, dataToEncrypt);
            byte[] decrypted = this._aesWrapper.Aes256Decrypt(aesNonce, key, encrypted);
            Assert.Equal(32, key.Length);
            Assert.NotNull(encrypted);
            Assert.True(decrypted.SequenceEqual(dataToEncrypt));
            // The salt is thrown away, so the same password gives a different key every time.
            Assert.NotEqual(key, this._argon2Wrapper.DeriveAES256Key(password));
            Assert.Throws<ArgumentNullException>(() => this._argon2Wrapper.DeriveAES256Key(null!));
            Assert.Throws<ArgumentException>(() => this._argon2Wrapper.DeriveAES256Key(""));
        }
#pragma warning restore CS0618
    }
}
