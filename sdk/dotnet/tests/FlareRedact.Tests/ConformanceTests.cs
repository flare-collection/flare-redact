using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace FlareRedact.Tests
{
    /// <summary>
    /// The .NET engine must agree with the JavaScript, Python, Go, Rust and Java engines, case for
    /// case (SPEC §13). This file is the .NET half of that promise.
    /// </summary>
    public class ConformanceTests
    {
        internal static string SpecDir()
        {
            string? configured = Environment.GetEnvironmentVariable("FLARE_SPEC_DIR");
            if (!string.IsNullOrEmpty(configured)) return Path.GetFullPath(configured);
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                string candidate = Path.Combine(dir.FullName, "spec", "conformance", "cases.json");
                if (File.Exists(candidate)) return Path.Combine(dir.FullName, "spec");
                dir = dir.Parent;
            }
            throw new InvalidOperationException("cannot find spec/conformance; set FLARE_SPEC_DIR");
        }

        internal static object? ReadJson(string path) => Json.Parse(File.ReadAllText(path));

        private static readonly Lazy<Dictionary<string, IDictionary<string, object?>>> Cases = new(() =>
        {
            var corpus = (IDictionary<string, object?>)ReadJson(Path.Combine(SpecDir(), "conformance", "cases.json"))!;
            var output = new Dictionary<string, IDictionary<string, object?>>(StringComparer.Ordinal);
            foreach (object? item in (IList<object?>)corpus["cases"]!)
            {
                var testCase = (IDictionary<string, object?>)item!;
                output[(string)testCase["name"]!] = testCase;
            }
            return output;
        });

        private static readonly Lazy<IDictionary<string, object?>> Expected = new(() =>
            (IDictionary<string, object?>)ReadJson(Path.Combine(SpecDir(), "conformance", "expected.json"))!);

        public static IEnumerable<object[]> CaseNames() => Cases.Value.Keys.Select(name => new object[] { name });

        private static double Round6(double value) => Math.Round(value * 1e6, MidpointRounding.AwayFromZero) / 1e6;

        private static Dictionary<string, object?> Normalise(Finding finding)
        {
            var output = new Dictionary<string, object?>
            {
                ["detector"] = finding.Detector,
                ["risk"] = finding.Risk.WireName(),
                ["confidence"] = Round6(finding.Confidence),
            };
            if (finding.Start >= 0)
            {
                output["start"] = (long)finding.Start;
                output["end"] = (long)finding.End;
                output["line"] = (long)finding.Line;
                output["column"] = (long)finding.Column;
            }
            if (finding.Path != null) output["path"] = finding.Path;
            if (finding.Value != null) output["value"] = finding.Value;
            return output;
        }

        internal static Dictionary<string, object?> RunCase(IDictionary<string, object?> testCase)
        {
            testCase.TryGetValue("input", out object? input);
            testCase.TryGetValue("options", out object? wire);
            RedactOptions options = RedactOptions.FromWire(wire as IDictionary<string, object?>);
            List<object?> checks = testCase.TryGetValue("checks", out object? c) && c is IList<object?> list
                ? list.ToList()
                : new List<object?> { "redact", "scan" };
            var result = new Dictionary<string, object?>();
            if (checks.Contains("redact")) result["redact"] = Policy.Compile(options).Redact(input);
            if (checks.Contains("scan"))
            {
                result["findings"] = Policy.Compile(options).Scan(input).Select(f => (object?)Normalise(f)).ToList();
            }
            if (checks.Contains("vault"))
            {
                var spec = testCase.TryGetValue("vault", out object? v) && v is IDictionary<string, object?> map
                    ? map
                    : new Dictionary<string, object?>();
                VaultOptions style = spec.TryGetValue("placeholderStyle", out object? s) && "readable".Equals(s)
                    ? VaultOptions.ReadablePlaceholders
                    : VaultOptions.OpaquePlaceholders;
                Vault vault = Vault.Create(options, style);
                object? redacted = vault.Redact(input);
                var output = new Dictionary<string, object?>
                {
                    ["redacted"] = redacted,
                    ["restored"] = vault.Restore(redacted),
                    ["entries"] = vault.Entries.Select(e => (object?)new List<object?> { e.Key, e.Value }).ToList(),
                };
                if (spec.TryGetValue("reply", out object? reply)) output["reply"] = vault.Restore(reply);
                result["vault"] = output;
            }
            return result;
        }

        /// <summary>Structural equality with every number compared as a double, as JSON has one number type.</summary>
        internal static bool JsonEquals(object? a, object? b)
        {
            if ((a is long || a is double) && (b is long || b is double)) return Convert.ToDouble(a) == Convert.ToDouble(b);
            if (a is IDictionary<string, object?> left && b is IDictionary<string, object?> right)
            {
                if (left.Count != right.Count) return false;
                foreach (KeyValuePair<string, object?> entry in left)
                {
                    if (!right.TryGetValue(entry.Key, out object? other) || !JsonEquals(entry.Value, other)) return false;
                }
                return true;
            }
            if (a is IList<object?> l && b is IList<object?> r)
            {
                if (l.Count != r.Count) return false;
                for (int i = 0; i < l.Count; i++)
                {
                    if (!JsonEquals(l[i], r[i])) return false;
                }
                return true;
            }
            return a == null ? b == null : a.Equals(b);
        }

        [Fact]
        public void CorpusAndExpectationsAgree()
        {
            Assert.Equal(Expected.Value.Count, Cases.Value.Count);
            Assert.True(Cases.Value.Count >= 222);
        }

        [Theory]
        [MemberData(nameof(CaseNames))]
        public void Case(string name)
        {
            Assert.True(Expected.Value.TryGetValue(name, out object? want), "no expectation for " + name);
            // A round trip through JSON gives both sides the same concrete types.
            object? got = Json.Parse(Json.Stringify(RunCase(Cases.Value[name])));
            if (!JsonEquals(got, want))
            {
                Assert.Fail("mismatch\n got: " + Json.Stringify(got) + "\nwant: " + Json.Stringify(want));
            }
        }

        [Fact]
        public void VendoredPackMatchesSpecification()
        {
            object? canonical = ReadJson(Path.Combine(SpecDir(), "detectors.json"));
            object? vendored = Json.Parse(Pack.ReadResource(Pack.CoreResource));
            Assert.True(JsonEquals(canonical, vendored),
                "the vendored pack has drifted from spec/detectors.json; run `node scripts/sync-spec.mjs`");
        }
    }
}
