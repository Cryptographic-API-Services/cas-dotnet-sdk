using System.Collections.Generic;
using System.Linq;
using CasDotnetSdk.Hashers;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests.Wycheproof
{
    /// <summary>
    /// Project Wycheproof HMAC-SHA256 vectors. The SDK exposes only HMAC-SHA256 and
    /// always returns the full 32-byte tag, so groups with a shorter tagSize are
    /// compared against the truncated tag (verify is only exercised for full-tag
    /// groups). The wrapper rejects empty keys and messages, so those vectors are
    /// skipped (counted).
    /// </summary>
    public class HmacWycheproofTests
    {
        private const int FullTagBytes = 32;
        private readonly HmacWrapper _wrapper = new HmacWrapper();

        [Fact]
        public void WycheproofHmacSha256Vectors()
        {
            var root = PqcVectorData.Load("wycheproof_hmac_sha256.json");
            int count = 0;
            int skippedEmpty = 0;
            var failures = new List<string>();

            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                int tagBytes = group.GetProperty("tagSize").GetInt32() / 8;
                bool isFullTag = tagBytes == FullTagBytes;

                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    string keyHex = test.GetProperty("key").GetString()!;
                    string msgHex = test.GetProperty("msg").GetString()!;
                    string tagHex = test.GetProperty("tag").GetString()!;
                    bool isValid = test.GetProperty("result").GetString() == "valid";

                    // The wrapper rejects an empty key or message.
                    if (keyHex.Length == 0 || msgHex.Length == 0)
                    {
                        skippedEmpty++;
                        continue;
                    }

                    byte[] key = PqcVectorData.Hex(keyHex);
                    byte[] msg = PqcVectorData.Hex(msgHex);
                    string computedTag = PqcVectorData.ToHex(_wrapper.HmacSignBytes(key, msg).Take(tagBytes).ToArray());
                    count++;

                    if (isValid)
                    {
                        if (computedTag != tagHex)
                        {
                            failures.Add($"tcId={tcId} tag mismatch");
                        }
                        else if (isFullTag && !_wrapper.HmacVerifyBytes(key, msg, PqcVectorData.Hex(tagHex)))
                        {
                            failures.Add($"tcId={tcId} verify rejected a valid tag");
                        }
                    }
                    else
                    {
                        if (computedTag == tagHex)
                        {
                            failures.Add($"tcId={tcId} invalid tag was reproduced");
                        }
                        else if (isFullTag && VerifyOrFalse(key, msg, tagHex))
                        {
                            failures.Add($"tcId={tcId} verify accepted an invalid tag");
                        }
                    }
                }
            }

            Assert.True(count > 0, "No HMAC-SHA256 vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} HMAC-SHA256 vectors failed (skippedEmpty={skippedEmpty}): {string.Join("; ", failures)}");
        }

        private bool VerifyOrFalse(byte[] key, byte[] msg, string tagHex)
        {
            try
            {
                // The wrapper rejects an empty signature up front.
                byte[] tag = PqcVectorData.Hex(tagHex);
                return tag.Length > 0 && _wrapper.HmacVerifyBytes(key, msg, tag);
            }
            catch
            {
                return false;
            }
        }
    }
}
