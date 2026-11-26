using System.Text.Json;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// Reads a NIST ACVP vector set from usnistgov/ACVP-Server's <c>internalProjection.json</c>,
    /// which holds the prompt (inputs) and the expected results of every test case in one file,
    /// so no join of <c>prompt.json</c> with <c>expectedResults.json</c> is needed.
    /// </summary>
    internal static class AcvpFile
    {
        /// <summary>One test case with the group it belongs to.</summary>
        internal readonly struct Case
        {
            public Case(JsonElement group, JsonElement test)
            {
                Group = group;
                Test = test;
            }

            public JsonElement Group { get; }

            public JsonElement Test { get; }

            public int TcId => Test.GetProperty("tcId").GetInt32();

            /// <summary>A test-case value, falling back to the group (e.g. EdDSA's d and q).</summary>
            public bool TryGet(string name, out JsonElement value)
            {
                return Test.TryGetProperty(name, out value) || Group.TryGetProperty(name, out value);
            }

            public string String(string name)
            {
                return TryGet(name, out JsonElement value)
                    ? value.GetString()!
                    : throw new KeyNotFoundException($"tcId {TcId} has no '{name}'.");
            }

            public byte[] Hex(string name)
            {
                string hex = String(name);
                return hex.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(hex);
            }

            public bool Bool(string name)
            {
                return TryGet(name, out JsonElement value) ? value.GetBoolean() : throw new KeyNotFoundException($"tcId {TcId} has no '{name}'.");
            }

            public int Int(string name)
            {
                return TryGet(name, out JsonElement value) ? value.GetInt32() : throw new KeyNotFoundException($"tcId {TcId} has no '{name}'.");
            }

            /// <summary>The context string, or empty when the case has none.</summary>
            public string Context => TryGet("context", out JsonElement value) ? value.GetString() ?? string.Empty : string.Empty;
        }

        /// <summary>
        /// Every test case of the vector set in <paramref name="directory"/>, checking that the file
        /// is the algorithm/mode expected.
        /// </summary>
        public static List<Case> Load(string directory, string algorithm, string? mode = null)
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(NistVectors.AcvpPath(directory)));
            JsonElement root = document.RootElement.Clone();
            if (root.GetProperty("algorithm").GetString() != algorithm ||
                (mode != null && root.GetProperty("mode").GetString() != mode))
            {
                throw new InvalidDataException($"{directory} isn't {algorithm} {mode}.");
            }

            var cases = new List<Case>();
            foreach (JsonElement group in root.GetProperty("testGroups").EnumerateArray())
            {
                foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
                {
                    cases.Add(new Case(group, test));
                }
            }
            if (cases.Count == 0)
            {
                throw new InvalidDataException($"{directory} has no test cases.");
            }
            return cases;
        }
    }
}
