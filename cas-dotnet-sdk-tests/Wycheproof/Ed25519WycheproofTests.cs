using System;
using System.Collections.Generic;
using System.Linq;
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

        /// <summary>
        /// Signing keys (32-byte seeds) whose public keys appear in the Wycheproof file: the
        /// RFC 8032 section 7.1 TEST 1 key, and the key Wycheproof generated its edge-case
        /// signatures (non-canonical R, s + nL, small-order R) with. The test derives each public
        /// key from its seed, so a wrong seed fails loudly instead of skipping vectors.
        /// </summary>
        private static readonly string[] KnownSigningKeys =
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "add4bb8103785baf9ac534258e8aaf65f5f1adb5ef5f3df19bb80ab989c4d64b",
        };

        [Fact]
        public void WycheproofEd25519BothVerifyMethodsAgree()
        {
            // #220: VerifyBytes (signing key) and VerifyWithPublicKeyBytes (public key) both use
            // verify_strict, so every vector must get the same answer from each, and the
            // non-canonical / malleable / small-order signatures must be rejected by both.
            var root = PqcVectorData.Load("wycheproof_ed25519.json");
            var keysByPublicKey = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string seedHex in KnownSigningKeys)
            {
                byte[] seed = PqcVectorData.Hex(seedHex);
                byte[] publicKey = _wrapper.SignBytes(seed, new byte[] { 0 }).PublicKey;
                keysByPublicKey[Convert.ToHexString(publicKey)] = seed;
            }

            int count = 0;
            int edgeCasesRejected = 0;
            var matchedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var failures = new List<string>();

            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                string pkHex = group.GetProperty("publicKey").GetProperty("pk").GetString()!;
                if (!keysByPublicKey.TryGetValue(pkHex, out byte[]? seed))
                {
                    continue;
                }
                matchedKeys.Add(pkHex);
                byte[] pk = PqcVectorData.Hex(pkHex);

                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    string msgHex = test.GetProperty("msg").GetString()!;
                    // The public verify API rejects empty input.
                    if (msgHex.Length == 0)
                    {
                        continue;
                    }

                    int tcId = test.GetProperty("tcId").GetInt32();
                    string result = test.GetProperty("result").GetString()!;
                    byte[] msg = PqcVectorData.Hex(msgHex);
                    byte[] sig = PqcVectorData.Hex(test.GetProperty("sig").GetString()!);
                    bool withPublicKey = Verify(() => _wrapper.VerifyWithPublicKeyBytes(pk, sig, msg));
#pragma warning disable CS0618 // VerifyBytes is obsolete; this test checks it agrees with VerifyWithPublicKeyBytes.
                    bool withSigningKey = Verify(() => _wrapper.VerifyBytes(seed, sig, msg));
#pragma warning restore CS0618
                    count++;

                    if (withPublicKey != withSigningKey)
                    {
                        failures.Add($"tcId={tcId} methods disagree (public key: {withPublicKey}, signing key: {withSigningKey})");
                    }
                    if (result == "valid" && !(withPublicKey && withSigningKey))
                    {
                        failures.Add($"tcId={tcId} valid signature rejected");
                    }
                    else if (result == "invalid" && (withPublicKey || withSigningKey))
                    {
                        failures.Add($"tcId={tcId} invalid signature accepted");
                    }

                    bool isEdgeCase = test.GetProperty("flags").EnumerateArray()
                        .Any(f => f.GetString() is "InvalidEncoding" or "SignatureMalleability");
                    if (isEdgeCase && result == "invalid" && !withPublicKey && !withSigningKey)
                    {
                        edgeCasesRejected++;
                    }
                }
            }

            Assert.Equal(KnownSigningKeys.Length, matchedKeys.Count);
            Assert.True(edgeCasesRejected > 0, "No non-canonical or malleable Ed25519 vectors were checked.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} Ed25519 vectors failed: {string.Join("; ", failures)}");
        }

        private static bool Verify(Func<bool> verify)
        {
            try
            {
                return verify();
            }
            catch
            {
                // A malformed (e.g. wrong-length) signature may throw instead of returning
                // false; both count as a rejection.
                return false;
            }
        }
    }
}
