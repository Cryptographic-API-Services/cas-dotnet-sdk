using System.Collections.Generic;
using CasDotnetSdk.Signatures;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests.Wycheproof
{
    /// <summary>
    /// Project Wycheproof Ed25519 signature-verification vectors. The SDK's verify
    /// API rejects an empty message, so empty-message vectors are skipped (counted).
    /// "acceptable" vectors (small- or mixed-order public keys) may be accepted or
    /// rejected, so only "valid" and "invalid" are asserted.
    /// </summary>
    public class Ed25519WycheproofTests
    {
        private readonly ED25519Wrapper _wrapper = new ED25519Wrapper();

        [Fact]
        public void WycheproofEd25519VerificationVectors()
        {
            var root = PqcVectorData.Load("wycheproof_ed25519.json");
            int count = 0;
            int skippedEmpty = 0;
            var failures = new List<string>();

            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                byte[] pk = PqcVectorData.Hex(group.GetProperty("publicKey").GetProperty("pk").GetString()!);
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    string msgHex = test.GetProperty("msg").GetString()!;
                    string result = test.GetProperty("result").GetString()!;

                    // The public verify API rejects empty input.
                    if (msgHex.Length == 0)
                    {
                        skippedEmpty++;
                        continue;
                    }

                    byte[] msg = PqcVectorData.Hex(msgHex);
                    byte[] sig = PqcVectorData.Hex(test.GetProperty("sig").GetString()!);

                    bool verified;
                    try
                    {
                        // A malformed (e.g. empty/wrong-length) signature may throw
                        // instead of returning false; both count as a rejection.
                        verified = _wrapper.VerifyWithPublicKeyBytes(pk, sig, msg);
                    }
                    catch
                    {
                        verified = false;
                    }
                    count++;

                    if (result == "valid" && !verified)
                    {
                        failures.Add($"tcId={tcId} valid signature rejected");
                    }
                    else if (result == "invalid" && verified)
                    {
                        failures.Add($"tcId={tcId} invalid signature accepted");
                    }
                }
            }

            Assert.True(count > 0, "No Ed25519 vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} Ed25519 vectors failed (skippedEmpty={skippedEmpty}): {string.Join("; ", failures)}");
        }
    }
}
