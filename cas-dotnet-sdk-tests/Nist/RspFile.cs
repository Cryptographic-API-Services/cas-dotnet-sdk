using System.Globalization;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// One vector from a NIST CAVP <c>.rsp</c> file: its fields, the <c>[section]</c> headers it
    /// sits under, and the section-level parameters (an RSA modulus, a Monte Carlo seed) that
    /// precede it.
    /// </summary>
    internal sealed class RspRecord
    {
        private readonly Dictionary<string, string> _fields;
        private readonly Dictionary<string, string> _parameters;

        public RspRecord(IReadOnlyDictionary<string, string> section, Dictionary<string, string> parameters, Dictionary<string, string> fields, bool failed, string? failureReason)
        {
            Section = section;
            _parameters = parameters;
            _fields = fields;
            Failed = failed;
            FailureReason = failureReason;
        }

        /// <summary>The <c>[key = value]</c> headers of the record's section.</summary>
        public IReadOnlyDictionary<string, string> Section { get; }

        /// <summary>
        /// The vector is expected to fail: a bare <c>FAIL</c> line (GCMVS) or
        /// <c>Result = F (n - reason)</c> (RSA2VS).
        /// </summary>
        public bool Failed { get; }

        /// <summary>The text after <c>Result = F</c>, e.g. <c>(3 - Signature changed )</c>.</summary>
        public string? FailureReason { get; }

        /// <summary>A record field, then a section parameter, then a section header.</summary>
        public string this[string key]
        {
            get
            {
                if (TryGet(key, out string? value))
                {
                    return value!;
                }
                throw new KeyNotFoundException($"'{key}' isn't in {this}.");
            }
        }

        public bool Has(string key)
        {
            return TryGet(key, out _);
        }

        public int Int(string key)
        {
            return int.Parse(this[key], NumberStyles.Integer, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Decodes a hex value. RSA2VS prints values as integers, dropping a leading zero nibble,
        /// so an odd-length value is left-padded with one <c>0</c>.
        /// </summary>
        public byte[] Bytes(string key)
        {
            string hex = this[key];
            if (hex.Length % 2 == 1)
            {
                hex = "0" + hex;
            }
            return hex.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(hex);
        }

        public override string ToString()
        {
            string section = string.Join(", ", Section.Select(h => $"{h.Key} = {h.Value}"));
            string id = _fields.FirstOrDefault(f => f.Key.Equals("Count", StringComparison.OrdinalIgnoreCase)).Value is string count
                ? $"Count = {count}"
                : string.Join(", ", _fields.Take(2).Select(f => $"{f.Key} = {(f.Value.Length > 16 ? f.Value.Substring(0, 16) + "..." : f.Value)}"));
            return $"[{section}] {id}";
        }

        private bool TryGet(string key, out string? value)
        {
            return _fields.TryGetValue(key, out value) || _parameters.TryGetValue(key, out value) || Section.TryGetValue(key, out value);
        }
    }

    /// <summary>
    /// Reads NIST CAVP <c>.rsp</c> response files. Every file the tests use has the same shape:
    /// <list type="bullet">
    /// <item><c>#</c> comments;</item>
    /// <item>runs of <c>[key = value]</c> section headers (<c>[Keylen = 128]</c>, <c>[L=32]</c>,
    /// <c>[mod = 2048]</c>), which start a new section;</item>
    /// <item>blank-line separated blocks of <c>key = value</c> lines. A block holding the record
    /// key (<c>Count</c>, <c>Len</c>, <c>SHAAlg</c>; compared case-insensitively, so <c>COUNT</c>
    /// matches) is a vector; any other block holds section parameters (<c>n = ...</c>,
    /// <c>Seed = ...</c>) for the vectors after it;</item>
    /// <item>a failing vector is marked by a bare <c>FAIL</c> line or <c>Result = F (n - ...)</c>.</item>
    /// </list>
    /// </summary>
    internal static class RspFile
    {
        public static List<RspRecord> Read(string fileName, string recordKey = "Count")
        {
            var records = new List<RspRecord>();
            var section = new Dictionary<string, string>(StringComparer.Ordinal);
            var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
            var block = new List<string>();
            bool inHeaders = false;

            void EndBlock()
            {
                if (block.Count == 0)
                {
                    return;
                }
                var fields = new Dictionary<string, string>(StringComparer.Ordinal);
                bool failed = false;
                string? reason = null;
                foreach (string line in block)
                {
                    int eq = line.IndexOf('=');
                    if (eq < 0)
                    {
                        if (line != "FAIL")
                        {
                            throw new InvalidDataException($"{fileName}: unexpected line '{line}'.");
                        }
                        failed = true;
                        continue;
                    }
                    string key = line.Substring(0, eq).Trim();
                    string value = line.Substring(eq + 1).Trim();
                    fields[key] = value;
                    if (key == "Result")
                    {
                        failed = value.StartsWith("F", StringComparison.Ordinal);
                        reason = failed ? value.Substring(1).Trim() : null;
                    }
                }
                block.Clear();

                if (fields.Keys.Any(k => k.Equals(recordKey, StringComparison.OrdinalIgnoreCase)))
                {
                    records.Add(new RspRecord(new Dictionary<string, string>(section), new Dictionary<string, string>(parameters), fields, failed, reason));
                }
                else
                {
                    foreach (var field in fields)
                    {
                        parameters[field.Key] = field.Value;
                    }
                }
            }

            foreach (string rawLine in File.ReadLines(NistVectors.CavpPath(fileName)))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }
                if (line.Length == 0)
                {
                    EndBlock();
                    continue;
                }
                if (line.StartsWith("[", StringComparison.Ordinal))
                {
                    EndBlock();
                    if (!inHeaders)
                    {
                        section.Clear();
                        parameters.Clear();
                        inHeaders = true;
                    }
                    string[] header = line.Trim('[', ']').Split('=', 2);
                    section[header[0].Trim()] = header.Length > 1 ? header[1].Trim() : string.Empty;
                    continue;
                }
                inHeaders = false;
                block.Add(line);
            }
            EndBlock();

            if (records.Count == 0)
            {
                throw new InvalidDataException($"{fileName}: no records with key '{recordKey}'.");
            }
            return records;
        }
    }
}
