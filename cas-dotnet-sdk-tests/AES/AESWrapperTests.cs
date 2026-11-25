using CasDotnetSdk.Helpers;
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
        public void Aes256Key()
        {
            byte[] key = this._aESWrapper.Aes256Key();
            Assert.NotEmpty(key);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanKey()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

            Assert.Equal(aliceAesKey, bobAesKey);
        }

        [Fact]
        public void Aes128X25519DiffieHellmanKey()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

            Assert.Equal(aliceAesKey, bobAesKey);
        }

        [Fact]
        public void X25519DerivedKeysAreBoundToCipherAndKeySize()
        {
            X25519SecretPublicKey alice = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bob = this._x25519Wrapper.GenerateSecretAndPublicKey();
            byte[] sharedSecret = this._x25519Wrapper.GenerateSharedSecret(alice.SecretKey, bob.PublicKey).SharedSecret;

            byte[] aes256Key = this._aESWrapper.Aes256KeyFromX25519SharedSecret(sharedSecret, alice.PublicKey, bob.PublicKey);
            byte[] aes128Key = this._aESWrapper.Aes128KeyFromX25519SharedSecret(sharedSecret, alice.PublicKey, bob.PublicKey);

            Assert.Equal(32, aes256Key.Length);
            Assert.Equal(16, aes128Key.Length);
            Assert.NotEqual(sharedSecret, aes256Key);
            Assert.NotEqual(aes256Key[..16], aes128Key);
        }

        [Fact]
        public void X25519DerivedKeyRejectsAllZeroSharedSecret()
        {
            X25519SecretPublicKey alice = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bob = this._x25519Wrapper.GenerateSecretAndPublicKey();

            CasException ex = Assert.Throws<CasException>(() => this._aESWrapper.Aes256KeyFromX25519SharedSecret(new byte[32], alice.PublicKey, bob.PublicKey));
            Assert.Equal(CasErrorCode.InvalidKey, ex.ErrorCode);
        }

        [Fact]
        public void Aes256X25519DiffieHellmanEncrypt()
        {
            X25519SecretPublicKey aliceSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SecretPublicKey bobSecretAndPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            X25519SharedSecret aliceSharedSecet = this._x25519Wrapper.GenerateSharedSecret(aliceSecretAndPublicKey.SecretKey, bobSecretAndPublicKey.PublicKey);
            X25519SharedSecret bobSharedSecet = this._x25519Wrapper.GenerateSharedSecret(bobSecretAndPublicKey.SecretKey, aliceSecretAndPublicKey.PublicKey);
            byte[] aliceAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes256KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

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
            byte[] aliceAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(aliceSharedSecet.SharedSecret, aliceSecretAndPublicKey.PublicKey, bobSecretAndPublicKey.PublicKey);
            byte[] bobAesKey = this._aESWrapper.Aes128KeyFromX25519SharedSecret(bobSharedSecet.SharedSecret, bobSecretAndPublicKey.PublicKey, aliceSecretAndPublicKey.PublicKey);

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

        [Theory]
        [MemberData(nameof(AES128NistAadDecryptVectors))]
        public void Aes128WithAadMatchesNistDecryptVectors(byte[] nonce, byte[] key, byte[] ciphertextAndTag, byte[] aad, byte[] expectedPlaintext, bool expectFailure)
        {
            AssertNistAadDecrypt(this._aESWrapper.Aes128Decrypt, this._aESWrapper.Aes128Encrypt, nonce, key, ciphertextAndTag, aad, expectedPlaintext, expectFailure);
        }

        [Theory]
        [MemberData(nameof(AES256NistAadDecryptVectors))]
        public void Aes256WithAadMatchesNistDecryptVectors(byte[] nonce, byte[] key, byte[] ciphertextAndTag, byte[] aad, byte[] expectedPlaintext, bool expectFailure)
        {
            AssertNistAadDecrypt(this._aESWrapper.Aes256Decrypt, this._aESWrapper.Aes256Encrypt, nonce, key, ciphertextAndTag, aad, expectedPlaintext, expectFailure);
        }

        private static void AssertNistAadDecrypt(
            Func<byte[], byte[], byte[], byte[]?, byte[]> decrypt,
            Func<byte[], byte[], byte[], byte[]?, byte[]> encrypt,
            byte[] nonce, byte[] key, byte[] ciphertextAndTag, byte[] aad, byte[] expectedPlaintext, bool expectFailure)
        {
            if (expectFailure)
            {
                CasException ex = Assert.Throws<CasException>(() => decrypt(nonce, key, ciphertextAndTag, aad));
                Assert.Equal(CasErrorCode.DecryptionFailed, ex.ErrorCode);
                return;
            }

            Assert.Equal(expectedPlaintext, decrypt(nonce, key, ciphertextAndTag, aad));
            Assert.Equal(ciphertextAndTag, encrypt(nonce, key, expectedPlaintext, aad));
        }

        public static IEnumerable<object[]> AES128NistAadDecryptVectors()
        {
            return LoadGcmAadDecryptVectors("gcmDecrypt128.rsp");
        }

        public static IEnumerable<object[]> AES256NistAadDecryptVectors()
        {
            return LoadGcmAadDecryptVectors("gcmDecrypt256.rsp");
        }

        // Yields the 96-bit IV, 128-bit tag cases (the only shape the SDK's AES-GCM takes) for
        // every AAD length, including the FAIL cases, as (IV, key, CT || tag, AAD, PT, FAIL).
        private static IEnumerable<object[]> LoadGcmAadDecryptVectors(string fileName)
        {
            Dictionary<string, string> header = new Dictionary<string, string>();
            Dictionary<string, string> fields = new Dictionary<string, string>();

            foreach (string rawLine in File.ReadLines(ResolveVectorPath(fileName)))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                if (line.StartsWith("[", StringComparison.Ordinal))
                {
                    string[] parts = line.Trim('[', ']').Split('=', 2);
                    header[parts[0].Trim()] = parts[1].Trim();
                    continue;
                }

                bool isFailure = line.Equals("FAIL", StringComparison.Ordinal);
                if (!isFailure)
                {
                    string[] parts = line.Split('=', 2);
                    fields[parts[0].Trim()] = parts.Length > 1 ? parts[1].Trim() : string.Empty;
                    if (parts[0].Trim() != "PT")
                    {
                        continue;
                    }
                }

                if (header.GetValueOrDefault("IVlen") == "96" && header.GetValueOrDefault("Taglen") == "128")
                {
                    yield return new object[]
                    {
                        HexToBytes(fields["IV"]),
                        HexToBytes(fields["Key"]),
                        HexToBytes(fields["CT"] + fields["Tag"]),
                        HexToBytes(fields["AAD"]),
                        isFailure ? Array.Empty<byte>() : HexToBytes(fields["PT"]),
                        isFailure
                    };
                }
                fields.Clear();
            }
        }

        public static IEnumerable<object[]> AES128NistVectors()
        {
            return LoadGcmEncryptVectors("gcmDecrypt128.rsp");
        }

        public static IEnumerable<object[]> AES256NistVectors()
        {
            return LoadGcmEncryptVectors("gcmDecrypt256.rsp");
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
            bool isFailureCase = false;

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
                    isFailureCase = false;
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
                    continue;
                }

                if (line.StartsWith("AAD =", StringComparison.Ordinal))
                {
                    continue;
                }

                if (line.Equals("FAIL", StringComparison.Ordinal))
                {
                    isFailureCase = true;
                    continue;
                }

                if (!line.StartsWith("PT =", StringComparison.Ordinal))
                {
                    continue;
                }

                ptHex = line["PT =".Length..].Trim();

                if (isFailureCase || ivBitLength != 96 || aadBitLength != 0)
                {
                    continue;
                }

                if (string.IsNullOrEmpty(keyHex) || string.IsNullOrEmpty(ivHex) || ctHex is null || ptHex is null)
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
