using System;
using System.Collections.Generic;
using System.Linq;
using CasDotnetSdk.KeyExchange;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests.Wycheproof
{
    /// <summary>
    /// Project Wycheproof X25519 vectors. x25519-dalek clamps the private key and
    /// masks the public key's high bit per RFC 7748, so "valid", "acceptable" and
    /// "invalid" vectors alike must produce the expected shared secret (low-order
    /// points yield an all-zero secret rather than an error).
    /// </summary>
    public class X25519WycheproofTests
    {
        private readonly X25519Wrapper _wrapper = new X25519Wrapper();

        [Fact]
        public void WycheproofX25519SharedSecretVectors()
        {
            var root = PqcVectorData.Load("wycheproof_x25519.json");
            int count = 0;
            var failures = new List<string>();

            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    byte[] priv = PqcVectorData.Hex(test.GetProperty("private").GetString()!);
                    byte[] pub = PqcVectorData.Hex(test.GetProperty("public").GetString()!);
                    byte[] expected = PqcVectorData.Hex(test.GetProperty("shared").GetString()!);
                    count++;

                    try
                    {
                        byte[] actual = _wrapper.GenerateSharedSecret(priv, pub).SharedSecret;
                        if (!actual.SequenceEqual(expected))
                        {
                            failures.Add($"tcId={tcId} shared secret mismatch");
                        }
                    }
                    catch (Exception ex)
                    {
                        failures.Add($"tcId={tcId} threw {ex.GetType().Name}");
                    }
                }
            }

            Assert.True(count > 0, "No X25519 vectors were loaded.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} X25519 vectors failed: {string.Join("; ", failures)}");
        }
    }
}
