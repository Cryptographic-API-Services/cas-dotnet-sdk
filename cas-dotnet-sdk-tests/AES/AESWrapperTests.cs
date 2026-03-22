using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.Symmetric;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class AESWrapperTests
    {
        private readonly AESWrapper _aESWrapper;
        private readonly X25519Wrapper _x25519Wrapper;
        private const string ProjectDataDirectory = "cas-dotnet-sdk-tests/AES/Data";
        private const string OutputDataDirectory = "AES/Data";

        public AESWrapperTests()
        {
            this._aESWrapper = new AESWrapper();
            this._x25519Wrapper = new X25519Wrapper();
        }

        [Fact]
        public void Aes128BytesEncrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes128Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonceKey, key, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void AesNonce()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            Assert.True(nonceKey.Length == 12);
        }

        [Fact]
        public void Aes128Key()
        {
            byte[] key = this._aESWrapper.Aes128Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Aes128BytesDecrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes128Key();
            byte[] dataToEncrypt = Encoding.ASCII.GetBytes("Thisisthedatathatne1233123123123123123edstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonceKey, key, dataToEncrypt);
            byte[] decrypted = this._aESWrapper.Aes128Decrypt(nonceKey, key, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
        }

        [Fact]
        public void Aes256Key()
        {
            byte[] key = this._aESWrapper.Aes256Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanKeyAndNonce()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            byte[] bobAesKey = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.Equal(aliceAesKey, bobAesKey);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanKeyAndNonce()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            byte[] bobAesKey = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.Equal(aliceAesKey, bobAesKey);
        }

        [Fact]
        public void Aes256BytesEncrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes256Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonceKey, key, dataToEncrypt);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes256BytesDecrypt()
        {
            byte[] nonceKey = this._aESWrapper.GenerateAESNonce();
            byte[] key = this._aESWrapper.Aes256Key();
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("ThisisthedatathatneedstobeEncrypted#@$*(&");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonceKey, key, dataToEncrypt);
            byte[] decrypted = this._aESWrapper.Aes256Decrypt(nonceKey, key, encrypted);
            Assert.Equal(dataToEncrypt, decrypted);
            Assert.NotEqual(dataToEncrypt, encrypted);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            byte[] bobAesKey = this._aESWrapper.Aes256KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.Equal(aliceAesKey, bobAesKey);
            byte[] nonce = this._aESWrapper.GenerateAESNonce();
            byte[] toEncrypt = Encoding.UTF8.GetBytes("EncryptThisText");
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonce, aliceAesKey, toEncrypt);
            byte[] plaintext = this._aESWrapper.Aes256Decrypt(nonce, bobAesKey, encrypted);
            Assert.Equal(toEncrypt, plaintext);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(aliceSharedSecet.SharedSecret);
            byte[] bobAesKey = this._aESWrapper.Aes128KeyNonceX25519DiffieHellman(bobSharedSecet.SharedSecret);

            Assert.Equal(aliceAesKey, bobAesKey);
            byte[] nonce = this._aESWrapper.GenerateAESNonce();
            byte[] toEncrypt = Encoding.UTF8.GetBytes("EncryptThisText");
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonce, aliceAesKey, toEncrypt);
            byte[] plaintext = this._aESWrapper.Aes128Decrypt(nonce, bobAesKey, encrypted);
            Assert.Equal(toEncrypt, plaintext);
        }

        [Theory]
        [MemberData(nameof(AES128NistVectors))]
        public void Aes128MatchesNistEncryptVectors(byte[] nonce, byte[] key, byte[] plaintext, byte[] expectedCiphertext)
        {
            byte[] encrypted = this._aESWrapper.Aes128Encrypt(nonce, key, plaintext);

            Assert.Equal(expectedCiphertext, encrypted.Take(expectedCiphertext.Length).ToArray());
        }

        [Theory]
        [MemberData(nameof(AES256NistVectors))]
        public void Aes256MatchesNistEncryptVectors(byte[] nonce, byte[] key, byte[] plaintext, byte[] expectedCiphertext)
        {
            byte[] encrypted = this._aESWrapper.Aes256Encrypt(nonce, key, plaintext);

            Assert.Equal(expectedCiphertext, encrypted.Take(expectedCiphertext.Length).ToArray());
        }

        public static IEnumerable<object[]> AES128NistVectors()
        {
            return LoadGcmEncryptVectors("gcmEncryptExtIV128.rsp");
        }

        public static IEnumerable<object[]> AES256NistVectors()
        {
            return LoadGcmEncryptVectors("gcmEncryptExtIV256.rsp");
        }

        private static IEnumerable<object[]> LoadGcmEncryptVectors(string fileName)
        {
            string path = ResolveVectorPath(fileName);

            string? keyHex = null;
            string? ivHex = null;
            string? ctHex = null;
            string? ptHex = null;
            int? ivBitLength = null;
            int? aadBitLength = null;

            foreach (string rawLine in File.ReadLines(path))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                if (line.StartsWith("[IVlen =", StringComparison.Ordinal))
                {
                    ivBitLength = ParseBracketValue(line, "IVlen");
                    continue;
                }

                if (line.StartsWith("[AADlen =", StringComparison.Ordinal))
                {
                    aadBitLength = ParseBracketValue(line, "AADlen");
                    continue;
                }

                if (line.StartsWith("[", StringComparison.Ordinal))
                {
                    continue;
                }

                if (line.StartsWith("Count =", StringComparison.Ordinal))
                {
                    ResetVectorState(
                        ref keyHex,
                        ref ivHex,
                        ref ctHex,
                        ref ptHex);
                    continue;
                }

                if (line.StartsWith("Key =", StringComparison.Ordinal))
                {
                    keyHex = line["Key =".Length..].Trim();
                    continue;
                }

                if (line.StartsWith("IV =", StringComparison.Ordinal))
                {
                    ivHex = line["IV =".Length..].Trim();
                    continue;
                }

                if (line.StartsWith("CT =", StringComparison.Ordinal))
                {
                    ctHex = line["CT =".Length..].Trim();

                    if (ivBitLength != 96 || aadBitLength != 0)
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(keyHex) || string.IsNullOrEmpty(ivHex) || string.IsNullOrEmpty(ctHex) || string.IsNullOrEmpty(ptHex))
                    {
                        continue;
                    }

                    yield return new object[]
                    {
                        HexToBytes(ivHex),
                        HexToBytes(keyHex),
                        HexToBytes(ptHex),
                        HexToBytes(ctHex)
                    };
                    continue;
                }

                if (line.StartsWith("AAD =", StringComparison.Ordinal))
                {
                    continue;
                }

                if (!line.StartsWith("PT =", StringComparison.Ordinal))
                {
                    continue;
                }

                ptHex = line["PT =".Length..].Trim();
            }
        }

        private static string ResolveVectorPath(string fileName)
        {
            string projectRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] candidatePaths =
            {
                Path.Combine(AppContext.BaseDirectory, OutputDataDirectory, fileName),
                Path.Combine(projectRoot, ProjectDataDirectory, fileName),
                Path.Combine(userProfile, "Downloads", "gcmtestvectors", fileName)
            };

            foreach (string candidatePath in candidatePaths)
            {
                if (File.Exists(candidatePath))
                {
                    return candidatePath;
                }
            }

            throw new FileNotFoundException(
                $"Missing AES-GCM vector file: {fileName}. Checked: {string.Join(", ", candidatePaths)}");
        }

        private static byte[] HexToBytes(string value)
        {
            return string.IsNullOrEmpty(value) ? Array.Empty<byte>() : Convert.FromHexString(value);
        }

        private static void ResetVectorState(
            ref string? keyHex,
            ref string? ivHex,
            ref string? ctHex,
            ref string? ptHex)
        {
            keyHex = null;
            ivHex = null;
            ctHex = null;
            ptHex = null;
        }

        private static int ParseBracketValue(string line, string fieldName)
        {
            string prefix = $"[{fieldName} =";
            string value = line[prefix.Length..].TrimEnd(']').Trim();
            return int.Parse(value);
        }
    }
}
