using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using CasDotnetSdk.PQC;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests
{
    public class MLDSAWrapperTests
    {
        private readonly MLDSAWrapper _wrapper;

        public MLDSAWrapperTests()
        {
            this._wrapper = new MLDSAWrapper();
        }

        [Fact]
        public void GenerateKeyPair()
        {
            var keyPair = this._wrapper.GenerateSigningAndVerificationKey();
            Assert.NotNull(keyPair);
            Assert.NotNull(keyPair.SigningKey);
            Assert.NotNull(keyPair.VerificationKey);
            // ML-DSA-65: 32-byte seed signing key, 1952-byte verification key.
            Assert.Equal(32, keyPair.SigningKey.Length);
            Assert.Equal(1952, keyPair.VerificationKey.Length);
        }

        [Fact]
        public void SignAndVerify()
        {
            var keyPair = this._wrapper.GenerateSigningAndVerificationKey();
            byte[] message = Encoding.UTF8.GetBytes("This is a test message.");
            byte[] signature = this._wrapper.Sign(keyPair.SigningKey, message);
            Assert.NotNull(signature);
            Assert.Equal(3309, signature.Length);
            Assert.True(this._wrapper.Verify(keyPair.VerificationKey, signature, message));

            byte[] modifiedMessage = Encoding.UTF8.GetBytes("This is a modified test message.");
            Assert.False(this._wrapper.Verify(keyPair.VerificationKey, signature, modifiedMessage));
        }

        [Fact]
        public void SignIsDeterministic()
        {
            var keyPair = this._wrapper.GenerateSigningAndVerificationKey();
            byte[] message = Encoding.UTF8.GetBytes("deterministic");
            byte[] first = this._wrapper.Sign(keyPair.SigningKey, message);
            byte[] second = this._wrapper.Sign(keyPair.SigningKey, message);
            Assert.Equal(first, second);
        }

        // NIST ACVP ML-DSA-65 (FIPS 204) sigVer known-answer vectors.
        // cas-lib verifies with an empty context, so only empty-context (external, pure) tests are included.
        [Fact]
        public void NistSignatureVerificationVectors()
        {
            var root = PqcVectorData.Load("nist_mldsa_65_sigver.json");
            int count = 0;
            var failures = new List<string>();
            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    byte[] pk = PqcVectorData.Hex(test.GetProperty("pk").GetString()!);
                    byte[] msg = PqcVectorData.Hex(test.GetProperty("message").GetString()!);
                    byte[] sig = PqcVectorData.Hex(test.GetProperty("signature").GetString()!);
                    bool expected = test.GetProperty("testPassed").GetBoolean();

                    bool actual;
                    try
                    {
                        actual = this._wrapper.Verify(pk, sig, msg);
                    }
                    catch
                    {
                        // A malformed key/signature is a verification failure.
                        actual = false;
                    }
                    if (actual != expected)
                    {
                        failures.Add($"tcId={tcId} expected={expected} actual={actual}");
                    }
                    count++;
                }
            }
            Assert.True(count > 0, "No NIST ML-DSA vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} NIST ML-DSA vectors mismatched: {string.Join("; ", failures)}");
        }

        // Project Wycheproof ML-DSA-65 verification vectors.
        // cas-lib verifies with an empty context, so tests that carry a non-empty ctx are skipped.
        [Fact]
        public void WycheproofSignatureVerificationVectors()
        {
            var root = PqcVectorData.Load("wycheproof_mldsa_65_verify.json");
            int count = 0;
            var failures = new List<string>();
            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                byte[] pk = PqcVectorData.Hex(group.GetProperty("publicKey").GetString()!);
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    if (test.TryGetProperty("ctx", out var ctx) && ctx.GetString()!.Length > 0)
                    {
                        continue;
                    }
                    int tcId = test.GetProperty("tcId").GetInt32();
                    byte[] msg = PqcVectorData.Hex(test.GetProperty("msg").GetString()!);
                    byte[] sig = PqcVectorData.Hex(test.GetProperty("sig").GetString()!);
                    bool expected = test.GetProperty("result").GetString() == "valid";

                    bool actual;
                    try
                    {
                        actual = this._wrapper.Verify(pk, sig, msg);
                    }
                    catch
                    {
                        actual = false;
                    }
                    if (actual != expected)
                    {
                        failures.Add($"tcId={tcId} expected={expected} actual={actual}");
                    }
                    count++;
                }
            }
            Assert.True(count > 0, "No Wycheproof ML-DSA vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} Wycheproof ML-DSA vectors mismatched: {string.Join("; ", failures)}");
        }

        // Project Wycheproof ML-DSA-65 deterministic signing (seed) vectors.
        // cas-lib signs deterministically with an empty context and takes the
        // 32-byte seed as the signing key, so vectors that need a non-empty
        // context, a hedged rnd, or a precomputed mu (Sign_internal, which carries
        // no message) can't be expressed through the API and are skipped (counted).
        [Fact]
        public void WycheproofSigningVectors()
        {
            var root = PqcVectorData.Load("wycheproof_mldsa_65_sign.json");
            int count = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                byte[] signingKey = PqcVectorData.Hex(group.GetProperty("privateSeed").GetString()!);
                byte[] verificationKey = PqcVectorData.Hex(group.GetProperty("publicKey").GetString()!);
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    string result = test.GetProperty("result").GetString()!;

                    // Unsupported: non-empty context, hedged rnd, or internal (no msg).
                    if ((test.TryGetProperty("ctx", out var ctx) && ctx.GetString()!.Length > 0) ||
                        (test.TryGetProperty("rnd", out var rnd) && rnd.GetString()!.Length > 0) ||
                        !test.TryGetProperty("msg", out var msgElement))
                    {
                        skipped++;
                        continue;
                    }

                    byte[] msg = PqcVectorData.Hex(msgElement.GetString()!);

                    if (result == "valid")
                    {
                        byte[] signature;
                        try
                        {
                            signature = this._wrapper.Sign(signingKey, msg);
                        }
                        catch (System.Exception ex)
                        {
                            failures.Add($"tcId={tcId} signing threw {ex.GetType().Name}");
                            count++;
                            continue;
                        }
                        if (PqcVectorData.ToHex(signature) != test.GetProperty("sig").GetString())
                        {
                            failures.Add($"tcId={tcId} signature mismatch");
                        }
                        else if (!this._wrapper.Verify(verificationKey, signature, msg))
                        {
                            failures.Add($"tcId={tcId} own signature did not verify");
                        }
                        count++;
                    }
                    else if (result == "invalid")
                    {
                        // An invalid signing key must be rejected.
                        bool threw = false;
                        try
                        {
                            this._wrapper.Sign(signingKey, msg);
                        }
                        catch
                        {
                            threw = true;
                        }
                        if (!threw)
                        {
                            failures.Add($"tcId={tcId} signing accepted an invalid private key");
                        }
                        count++;
                    }
                    else
                    {
                        // "acceptable" may go either way.
                        skipped++;
                    }
                }
            }
            Assert.True(count > 0, "No Wycheproof ML-DSA signing vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} Wycheproof ML-DSA signing vectors failed (skipped={skipped}): {string.Join("; ", failures)}");
        }
    }
}
