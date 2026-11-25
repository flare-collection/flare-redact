using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>A loaded, compiled FRS-1 detector pack.</summary>
    /// <remarks>
    /// Loading is strict on purpose. A pack that uses a construct this engine cannot run exactly
    /// as the specification describes (a lookahead, a <c>\d</c> whose meaning differs between
    /// languages, a checksum this build does not know) fails with a <see cref="PackException"/>.
    /// Failing open is how a redactor leaks.
    /// </remarks>
    public sealed class Pack
    {
        /// <summary>The FRS-1 revision this engine implements.</summary>
        public const string SpecRevision = "FRS-1";

        internal const string CoreResource = "FlareRedact.detectors.json";

        private const string Lower = "abcdefghijklmnopqrstuvwxyz";
        private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string Digits = "0123456789";

        private static readonly Dictionary<string, string> BoundaryClasses = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["word"] = Lower + Upper + Digits + "_",
            ["alnum"] = Lower + Upper + Digits,
            ["digit"] = Digits,
            ["hex"] = Digits + "abcdefABCDEF",
            ["base64"] = Lower + Upper + Digits + "+/=",
            ["base64url"] = Lower + Upper + Digits + "_+/=-",
            ["word_dash"] = Lower + Upper + Digits + "_-",
        };

        private const string ForbiddenEscapes = "bBdDwWsSpP123456789AZzGkK";

#if NET8_0_OR_GREATER
        // A pack is compiled once and scanned with many times; on .NET 8 compiling its patterns
        // to IL costs tens of milliseconds and makes every scan several times faster.
        private const RegexOptions PackRegexOptions = RegexOptions.CultureInvariant | RegexOptions.Compiled;
#else
        private const RegexOptions PackRegexOptions = RegexOptions.CultureInvariant;
#endif

        private static readonly Lazy<Pack> CorePack = new Lazy<Pack>(LoadCore);

        private readonly Dictionary<string, Detector> _byId;

        private Pack(string id, string version, string title, List<Detector> detectors, ConfidenceModel? model)
        {
            Id = id;
            Version = version;
            Title = title;
            Detectors = new ReadOnlyCollection<Detector>(detectors);
            _byId = new Dictionary<string, Detector>(StringComparer.Ordinal);
            foreach (Detector detector in detectors) _byId[detector.Id] = detector;
            Model = model;
        }

        /// <summary>The pack identifier, such as <c>flare-redact/core</c>.</summary>
        public string Id { get; }

        /// <summary>The pack version.</summary>
        public string Version { get; }

        /// <summary>The human-readable title.</summary>
        public string Title { get; }

        /// <summary>The detectors, in evaluation order.</summary>
        public IReadOnlyList<Detector> Detectors { get; }

        /// <summary>The learned confidence classifier, or null when the pack has none.</summary>
        public ConfidenceModel? Model { get; }

        /// <summary>The detector with an id, or null.</summary>
        public Detector? GetDetector(string detectorId) => _byId.TryGetValue(detectorId, out Detector? d) ? d : null;

        /// <summary>The bundled <c>flare-redact/core</c> pack, compiled once per process.</summary>
        public static Pack Core => CorePack.Value;

        internal static string ReadResource(string name)
        {
            using Stream? stream = typeof(Pack).Assembly.GetManifestResourceStream(name);
            if (stream == null) throw new PackException(name + " is missing from the assembly");
            using var reader = new StreamReader(stream, new UTF8Encoding(false));
            return reader.ReadToEnd();
        }

        private static Pack LoadCore() => Load(ReadResource(CoreResource));

        /// <summary>Compile an FRS-1 pack document.</summary>
        /// <param name="json">The pack as JSON text.</param>
        /// <exception cref="PackException">Anything this engine cannot honour exactly.</exception>
        public static Pack Load(string json)
        {
            object? parsed;
            try
            {
                parsed = Json.Parse(json);
            }
            catch (FormatException error)
            {
                throw new PackException("pack is not valid JSON: " + error.Message);
            }
            if (!(parsed is IDictionary<string, object?> document)) throw new PackException("a pack must be a JSON object");
            if (!(Get(document, "spec") is string spec) || spec != SpecRevision)
            {
                throw new PackException("unsupported pack revision " + Json.Stringify(Get(document, "spec"))
                    + "; this engine implements " + SpecRevision);
            }
            if (!(Get(document, "detectors") is IList<object?> detectorList) || detectorList.Count == 0)
            {
                throw new PackException("a pack must declare at least one detector");
            }
            var detectors = new List<Detector>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (object? item in detectorList)
            {
                if (!(item is IDictionary<string, object?> detectorSpec)) throw new PackException("every detector must be a JSON object");
                Detector detector = CompileDetector(detectorSpec);
                if (!seen.Add(detector.Id)) throw new PackException("duplicate detector id \"" + detector.Id + "\"");
                detectors.Add(detector);
            }
            ConfidenceModel? model = null;
            if (Get(document, "confidenceModel") is IDictionary<string, object?> modelSpec)
            {
                List<string> features = List(Get(modelSpec, "features")).Select(f => Text(f)).ToList();
                double[] weights = List(Get(modelSpec, "weights")).Select(w => Number(w, 0)).ToArray();
                model = new ConfidenceModel((int)Number(Get(modelSpec, "version"), 0), features, weights,
                    Number(Get(modelSpec, "bias"), 0));
            }
            string id = Str(Get(document, "id"));
            string title = Get(document, "title") is string t ? t : id;
            return new Pack(id, Str(Get(document, "version")), title, detectors, model);
        }

        internal static object? Get(IDictionary<string, object?> map, string key) =>
            map.TryGetValue(key, out object? value) ? value : null;

        private static IList<object?> List(object? value) => value as IList<object?> ?? Array.Empty<object?>();

        private static string Str(object? value) => value as string ?? "";

        /// <summary>A value as JavaScript's <c>String()</c> would write it.</summary>
        private static string Text(object? value) => value switch
        {
            null => "null",
            string s => s,
            bool b => b ? "true" : "false",
            double d => Json.FormatDouble(d),
            _ => Json.Stringify(value),
        };

        internal static double Number(object? value, double fallback) => value switch
        {
            long l => l,
            double d => d,
            int i => i,
            _ => fallback,
        };

        /// <summary>Reject constructs whose meaning differs between the FRS-1 target engines.</summary>
        internal static void AssertPortable(string pattern, string where)
        {
            int index = 0;
            bool inClass = false;
            while (index < pattern.Length)
            {
                char ch = pattern[index];
                if (ch == '\\')
                {
                    if (index + 1 >= pattern.Length) throw new PackException(where + ": pattern ends with a dangling backslash");
                    char next = pattern[index + 1];
                    if (ForbiddenEscapes.IndexOf(next) >= 0)
                    {
                        throw new PackException(where + ": '\\" + next + "' is not portable across FRS-1 engines;"
                            + " write the character class out, or use {{ANY}} / {{L}}");
                    }
                    index += 2;
                    continue;
                }
                if (inClass)
                {
                    if (ch == ']') inClass = false;
                    index++;
                    continue;
                }
                if (ch == '[')
                {
                    index++;
                    if (index < pattern.Length && pattern[index] == '^') index++;
                    if (index < pattern.Length && pattern[index] == ']') index++;
                    inClass = true;
                    continue;
                }
                if (ch == '(' && index + 1 < pattern.Length && pattern[index + 1] == '?')
                {
                    if (index + 2 >= pattern.Length || pattern[index + 2] != ':')
                    {
                        throw new PackException(where + ": only '(...)' and '(?:...)' groups are portable across FRS-1 engines");
                    }
                    index += 3;
                    continue;
                }
                if (ch == '^' || ch == '$') throw new PackException(where + ": anchors are not allowed inside a detector pattern");
                index++;
            }
            if (inClass) throw new PackException(where + ": unterminated character class");
        }

        /// <summary>How a compiled pattern is anchored.</summary>
        internal enum Anchor
        {
            /// <summary>Found anywhere.</summary>
            None,
            /// <summary>Must match at the start (Java's <c>lookingAt</c>).</summary>
            Start,
            /// <summary>Must match the whole input.</summary>
            Whole,
        }

        internal static Regex Compile(string pattern, string? flags, string where, bool portable, Anchor anchor = Anchor.None)
        {
            if (portable) AssertPortable(pattern, where);
            try
            {
                string translated = PatternTranslator.Translate(pattern, flags != null && flags.Contains("i"));
                string source = anchor switch
                {
                    Anchor.Start => "^(?:" + translated + ")",
                    Anchor.Whole => "^(?:" + translated + ")\\z",
                    _ => translated,
                };
                return new Regex(source, PackRegexOptions);
            }
            catch (ArgumentException error)
            {
                throw new PackException(where + ": invalid pattern (" + error.Message + ")");
            }
        }

        private static Detector CompileDetector(IDictionary<string, object?> spec)
        {
            foreach (string field in new[] { "id", "label", "why", "pattern", "mask", "default", "risk", "confidence" })
            {
                if (Get(spec, field) == null) throw new PackException("detector is missing required field \"" + field + "\"");
            }
            string where = "detector \"" + Text(Get(spec, "id")) + "\"";
            Risk risk = WireNames.ParseRisk(Str(Get(spec, "risk")))
                ?? throw new PackException(where + ": risk must be one of low, medium, high, critical");
            double confidence = Number(Get(spec, "confidence"), -1);
            if (!(confidence >= 0 && confidence <= 1)) throw new PackException(where + ": confidence must be between 0 and 1");
            string flags = Get(spec, "flags") as string ?? "";
            if (flags.Length > 0 && flags != "i") throw new PackException(where + ": only the 'i' flag is portable");

            var detector = new Detector(
                Str(Get(spec, "id")), Str(Get(spec, "label")), Str(Get(spec, "why")), risk, confidence,
                Get(spec, "default") is bool on && on,
                List(Get(spec, "tags")).Select(tag => Text(tag)),
                (int)Number(Get(spec, "priority"), 0),
                Get(spec, "refine") is bool refine && refine);

            Regex pattern = Compile(Str(Get(spec, "pattern")), flags, where, true);
            if (pattern.IsMatch("")) throw new PackException(where + ": pattern matches the empty string");
            detector.Pattern = pattern;
            detector.Capture = (int)Number(Get(spec, "capture"), 0);
            if (detector.Capture > pattern.GetGroupNumbers().Length - 1)
            {
                throw new PackException(where + ": capture group " + detector.Capture + " does not exist");
            }

            if (Get(spec, "boundary") is IDictionary<string, object?> boundary)
            {
                detector.Before = BoundaryClass(Get(boundary, "before"), where);
                detector.After = BoundaryClass(Get(boundary, "after"), where);
            }

            IList<object?> prefilter = List(Get(spec, "prefilter"));
            if (prefilter.Count > 0)
            {
                string alternation = string.Join("|", prefilter.Select(literal => PatternTranslator.Literal(Text(literal), true)));
                detector.Prefilter = new Regex(alternation, RegexOptions.CultureInvariant);
            }

            foreach (object? reject in List(Get(spec, "reject")))
            {
                detector.Reject.Add(Compile(Text(reject), flags, where + " reject", false, Anchor.Start));
            }
            foreach (object? validator in List(Get(spec, "validators")))
            {
                if (!(validator is IDictionary<string, object?> validatorSpec)) throw new PackException(where + ": every validator must be a JSON object");
                detector.Validators.Add(BuildValidator(validatorSpec, where));
            }
            if (!(Get(spec, "mask") is IDictionary<string, object?> mask)) throw new PackException(where + ": mask must be a JSON object");
            detector.Mask = BuildMask(mask, where);

            if (Get(spec, "context") is IDictionary<string, object?> context)
            {
                if (Get(context, "positive") is string positive)
                {
                    detector.ContextPositive = Compile(positive, "i", where + " context", false);
                }
                if (Get(context, "negative") is string negative)
                {
                    detector.ContextNegative = Compile(negative, "i", where + " context", false);
                }
                int window = (int)Number(Get(context, "window"), 0);
                if (window > 0) detector.ContextWindow = window;
            }
            return detector;
        }

        private static string? BoundaryClass(object? name, string where)
        {
            if (name == null) return null;
            string key = Text(name);
            if (!BoundaryClasses.TryGetValue(key, out string? members)) throw new PackException(where + ": unknown boundary class \"" + key + "\"");
            return members;
        }

        private static Func<string, bool> BuildValidator(IDictionary<string, object?> spec, string where)
        {
            string name = Str(Get(spec, "name"));
            switch (name)
            {
                case "normalized_match":
                {
                    Regex? strip = Get(spec, "strip") is string s && s.Length > 0
                        ? Compile(s, "", where + " validator strip", false)
                        : null;
                    Regex target = Compile(Str(Get(spec, "pattern")), "", where + " validator", false, Anchor.Whole);
                    return value => target.IsMatch(strip == null ? value : strip.Replace(value, ""));
                }
                case "luhn":
                {
                    int min = (int)Number(Get(spec, "minDigits"), 2);
                    int max = (int)Number(Get(spec, "maxDigits"), 0);
                    return value => Checksums.Luhn(value, min, max);
                }
                case "entropy":
                {
                    double min = Number(Get(spec, "min"), 0);
                    return value => Checksums.ShannonEntropy(value) >= min;
                }
                default:
                    if (!Checksums.Named.TryGetValue(name, out Func<string, bool>? named))
                    {
                        throw new PackException(where + ": unknown validator \"" + name + "\"; refusing to load a pack"
                            + " whose checks this engine cannot perform");
                    }
                    return named;
            }
        }

        private static Func<string, string> BuildMask(IDictionary<string, object?> spec, string where)
        {
            string type = Str(Get(spec, "type"));
            switch (type)
            {
                case "fixed":
                {
                    string text = Get(spec, "text") as string ?? "***";
                    return _ => text;
                }
                case "keepPrefix":
                {
                    int n = (int)Number(Get(spec, "n"), 0);
                    return value => value.Length <= n ? "***" : value.Substring(0, n) + "***";
                }
                case "keepLast":
                {
                    int n = (int)Number(Get(spec, "n"), 0);
                    return value =>
                    {
                        string digits = Checksums.DigitsOf(value);
                        string tail = digits.Length > n ? digits.Substring(digits.Length - n) : digits;
                        int groups = digits.Length > n ? (digits.Length - n + 3) / 4 : 0;
                        var output = new StringBuilder();
                        for (int i = 0; i < groups; i++) output.Append("**** ");
                        return output.Append(tail).ToString().Trim();
                    };
                }
                case "keepThroughSeparator":
                {
                    string separator = Str(Get(spec, "separator"));
                    int count = (int)Number(Get(spec, "count"), 1);
                    return value =>
                    {
                        int index = -separator.Length;
                        for (int n = 0; n < count; n++)
                        {
                            index = value.IndexOf(separator, index + separator.Length, StringComparison.Ordinal);
                            if (index < 0) return "***";
                        }
                        return value.Substring(0, index + separator.Length) + "***";
                    };
                }
                case "replace":
                {
                    string flags = Get(spec, "flags") as string ?? "";
                    Regex pattern = Compile(Str(Get(spec, "pattern")), flags, where + " mask", false, Anchor.Whole);
                    string replacement = Str(Get(spec, "replacement"));
                    return value =>
                    {
                        Match match = pattern.Match(value);
                        return match.Success ? ExpandReplacement(replacement, match) : value;
                    };
                }
                default:
                    throw new PackException(where + ": unknown mask type \"" + type + "\"");
            }
        }

        /// <summary>Substitute <c>$1</c>...<c>$9</c> and <c>$$</c> in a mask replacement template.</summary>
        private static string ExpandReplacement(string template, Match match)
        {
            var output = new StringBuilder();
            for (int i = 0; i < template.Length; i++)
            {
                char c = template[i];
                if (c == '$' && i + 1 < template.Length)
                {
                    char next = template[i + 1];
                    if (next == '$')
                    {
                        output.Append('$');
                        i++;
                        continue;
                    }
                    if (next >= '1' && next <= '9')
                    {
                        int group = next - '0';
                        if (group < match.Groups.Count && match.Groups[group].Success) output.Append(match.Groups[group].Value);
                        i++;
                        continue;
                    }
                }
                output.Append(c);
            }
            return output.ToString();
        }
    }
}
