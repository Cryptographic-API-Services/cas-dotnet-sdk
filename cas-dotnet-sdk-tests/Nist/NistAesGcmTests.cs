using CasDotnetSdk.Helpers;
using CasDotnetSdk.Symmetric;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST CAVP AES-GCM (GCMVS) vectors in the directions the <c>AESWrapperTests</c> decrypt
    /// tests don't cover. Only the 96-bit IV / 128-bit tag sections run (the API takes a 96-bit
    /// nonce and appends a 128-bit tag); the others are skipped.
    /// <list type="bullet">
    /// <item><c>gcmEncryptExtIV128/256.rsp</c> (encrypt with an external IV) against
    /// <c>Aes*Encrypt(nonce, key, plaintext, aad)</c>.</item>
    /// <item><c>gcmDecrypt128/256.rsp</c> against <c>Aes*Open</c>, by laying each vector out in the
    /// sealed format <c>IV || CT || Tag</c>. <c>FAIL</c> vectors must be rejected.</item>
    /// </list>
    /// </summary>
    public class NistAesGcmTests
    {
        private readonly AESWrapper _wrapper = new AESWrapper();

        [Theory]
        [InlineData("gcmEncryptExtIV128.rsp", 128)]
        [InlineData("gcmEncryptExtIV256.rsp", 256)]
        public void EncryptMatchesNistEncryptExtIvVectors(string fileName, int keyBits)
        {
            Func<byte[], byte[], byte[], byte[]?, byte[]> encrypt = keyBits == 128 ? this._wrapper.Aes128Encrypt : this._wrapper.Aes256Encrypt;
            Func<byte[], byte[], byte[], byte[]?, byte[]> decrypt = keyBits == 128 ? this._wrapper.Aes128Decrypt : this._wrapper.Aes256Decrypt;
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (RspRecord record in RspFile.Read(fileName))
            {
                Assert.Equal(keyBits.ToString(), record["Keylen"]);
                if (record["IVlen"] != "96" || record["Taglen"] != "128")
                {
                    skipped++;
                    continue;
                }
                run++;

                byte[] key = record.Bytes("Key");
                byte[] iv = record.Bytes("IV");
                byte[] plaintext = record.Bytes("PT");
                byte[] aad = record.Bytes("AAD");
                byte[] expected = record.Bytes("CT").Concat(record.Bytes("Tag")).ToArray();

                byte[] actual = encrypt(iv, key, plaintext, aad);
                if (!actual.SequenceEqual(expected))
                {
                    failures.Add($"{record} mismatched");
                }
                else if (!decrypt(iv, key, actual, aad).SequenceEqual(plaintext))
                {
                    failures.Add($"{record} did not decrypt");
                }
            }

            NistVectors.AssertCounts(fileName, 375, 7500, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST AES-{keyBits}-GCM encrypt vectors failed: {string.Join(", ", failures)}");
        }

        [Theory]
        [InlineData("gcmDecrypt128.rsp", 128, 196)]
        [InlineData("gcmDecrypt256.rsp", 256, 191)]
        public void OpenMatchesNistDecryptVectors(string fileName, int keyBits, int expectedFailures)
        {
            Func<byte[], byte[], byte[]?, byte[]> open = keyBits == 128 ? this._wrapper.Aes128Open : this._wrapper.Aes256Open;
            int run = 0;
            int skipped = 0;
            int rejected = 0;
            var failures = new List<string>();
            foreach (RspRecord record in RspFile.Read(fileName))
            {
                if (record["IVlen"] != "96" || record["Taglen"] != "128")
                {
                    skipped++;
                    continue;
                }
                run++;

                byte[] key = record.Bytes("Key");
                byte[] sealedMessage = record.Bytes("IV").Concat(record.Bytes("CT")).Concat(record.Bytes("Tag")).ToArray();
                byte[] aad = record.Bytes("AAD");
                if (record.Failed)
                {
                    try
                    {
                        open(key, sealedMessage, aad);
                        failures.Add($"{record} (FAIL) opened");
                    }
                    catch (CasException ex) when (ex.ErrorCode == CasErrorCode.DecryptionFailed)
                    {
                        rejected++;
                    }
                }
                else if (!open(key, sealedMessage, aad).SequenceEqual(record.Bytes("PT")))
                {
                    failures.Add($"{record} mismatched");
                }
            }

            NistVectors.AssertCounts(fileName, 375, 7500, run, skipped);
            Assert.Equal(expectedFailures, rejected + failures.Count(f => f.EndsWith("opened", StringComparison.Ordinal)));
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST AES-{keyBits}-GCM open vectors failed: {string.Join(", ", failures)}");
        }
    }
}
