using System.Collections.Generic;
using System.Linq;
using CasDotnetSdk.Symmetric;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests.Wycheproof
{
    /// <summary>
    /// Project Wycheproof AES-GCM vectors. The SDK's AES-GCM API takes a 96-bit
    /// nonce, appends the 128-bit tag to the ciphertext, has no AAD parameter and
    /// exposes only 128- and 256-bit keys, so only vectors matching those
    /// constraints are usable. Groups with a different IV/tag size or key length,
    /// and tests that carry AAD, are skipped.
    /// </summary>
    public class AesGcmWycheproofTests
    {
        private readonly AESWrapper _wrapper = new AESWrapper();

        [Theory]
        [InlineData(128)]
        [InlineData(256)]
        public void WycheproofAesGcmVectors(int keySize)
        {
            var root = PqcVectorData.Load("wycheproof_aes_gcm.json");
            int count = 0;
            var failures = new List<string>();

            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                if (group.GetProperty("ivSize").GetInt32() != 96 ||
                    group.GetProperty("tagSize").GetInt32() != 128 ||
                    group.GetProperty("keySize").GetInt32() != keySize)
                {
                    continue;
                }

                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    // The API has no AAD parameter.
                    if (test.GetProperty("aad").GetString()!.Length > 0)
                    {
                        continue;
                    }

                    int tcId = test.GetProperty("tcId").GetInt32();
                    byte[] key = PqcVectorData.Hex(test.GetProperty("key").GetString()!);
                    byte[] iv = PqcVectorData.Hex(test.GetProperty("iv").GetString()!);
                    byte[] msg = PqcVectorData.Hex(test.GetProperty("msg").GetString()!);
                    // cas-lib expects (and returns) the tag appended to the ciphertext.
                    byte[] ctWithTag = PqcVectorData.Hex(
                        test.GetProperty("ct").GetString()! + test.GetProperty("tag").GetString()!);
                    bool isValid = test.GetProperty("result").GetString() == "valid";
                    count++;

                    if (isValid)
                    {
                        byte[] ciphertext = Encrypt(keySize, iv, key, msg);
                        if (!ciphertext.SequenceEqual(ctWithTag))
                        {
                            failures.Add($"tcId={tcId} ciphertext||tag mismatch");
                            continue;
                        }
                        byte[] plaintext = Decrypt(keySize, iv, key, ctWithTag);
                        if (!plaintext.SequenceEqual(msg))
                        {
                            failures.Add($"tcId={tcId} plaintext mismatch");
                        }
                    }
                    else
                    {
                        // An invalid / acceptable ciphertext+tag must be rejected.
                        if (!ThrowsOnDecrypt(keySize, iv, key, ctWithTag))
                        {
                            failures.Add($"tcId={tcId} invalid ciphertext/tag was accepted");
                        }
                    }
                }
            }

            Assert.True(count > 0, $"No usable AES-{keySize} GCM vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} AES-{keySize} GCM vectors failed: {string.Join("; ", failures)}");
        }

        private byte[] Encrypt(int keySize, byte[] iv, byte[] key, byte[] msg)
            => keySize == 128 ? _wrapper.Aes128Encrypt(iv, key, msg) : _wrapper.Aes256Encrypt(iv, key, msg);

        private byte[] Decrypt(int keySize, byte[] iv, byte[] key, byte[] data)
            => keySize == 128 ? _wrapper.Aes128Decrypt(iv, key, data) : _wrapper.Aes256Decrypt(iv, key, data);

        private bool ThrowsOnDecrypt(int keySize, byte[] iv, byte[] key, byte[] data)
        {
            try
            {
                Decrypt(keySize, iv, key, data);
                return false;
            }
            catch
            {
                return true;
            }
        }
    }
}
