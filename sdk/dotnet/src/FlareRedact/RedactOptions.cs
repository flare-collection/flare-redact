using System;
using System.Collections.Generic;
using System.Linq;

namespace FlareRedact
{
    /// <summary>
    /// Everything that shapes a redaction. A new <see cref="RedactOptions"/> is a working
    /// configuration: the default detectors, mask mode and key redaction on.
    /// </summary>
    /// <remarks>
    /// <see cref="Policy.Compile"/> takes a snapshot, so changing an options object afterwards does
    /// not change a compiled policy. <see cref="FromJson"/> and <see cref="FromWire"/> read the JSON
    /// wire format (the JavaScript library's camelCase option names), so one document configures
    /// every engine.
    /// </remarks>
    public sealed class RedactOptions
    {
        /// <summary>Default cap on the UTF-16 length of one scanned string: 16 MiB.</summary>
        public const int DefaultMaxInputLength = 16 * 1024 * 1024;

        /// <summary>Default cap on findings per scanned string.</summary>
        public const int DefaultMaxFindings = 50_000;

        private static readonly HashSet<string> WireOptionNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "only", "enable", "disable", "mode", "mask", "transformSecret", "redactKeys", "allow", "terms",
            "termsCaseSensitive", "minConfidence", "refineConfidence", "includeValues", "limits",
        };

        /// <summary>Use exactly these detector ids or tags, ignoring defaults.</summary>
        public IList<string> Only { get; set; } = new List<string>();

        /// <summary>Turn on non-default detectors by id or tag.</summary>
        public IList<string> Enable { get; set; } = new List<string>();

        /// <summary>Turn off detectors by id or tag.</summary>
        public IList<string> Disable { get; set; } = new List<string>();

        /// <summary>The replacement strategy.</summary>
        public Mode Mode { get; set; } = Mode.Mask;

        /// <summary>A fixed replacement string; wins over the mode.</summary>
        public string? Mask { get; set; }

        /// <summary>Replace a matched value with your own function; wins over the mask and the mode.</summary>
        public Func<string, Detector, string>? MaskFunction { get; set; }

        /// <summary>The key for hash, pseudonym and surrogate modes. Never hard-code it.</summary>
        public string TransformSecret { get; set; } = "";

        /// <summary>The "sensitive by field name" rule: on by default.</summary>
        public bool RedactKeys { get; set; } = true;

        /// <summary>
        /// When set (and <see cref="RedactKeys"/> is on), an exact list of field names replacing the
        /// built-in sensitive-name test, compared after the key normalisation of SPEC §9. An empty
        /// list matches no key.
        /// </summary>
        public IList<string>? KeyNames { get; set; }

        /// <summary>Values that are never redacted.</summary>
        public IList<string> Allow { get; set; } = new List<string>();

        /// <summary>An additional test for values that are never redacted.</summary>
        public Func<string, bool>? AllowPredicate { get; set; }

        /// <summary>Your own words and phrases to always catch. A plain string converts to a <see cref="Term"/>.</summary>
        public IList<Term> Terms { get; set; } = new List<Term>();

        /// <summary>Match terms exactly as written (default: case-insensitive).</summary>
        public bool TermsCaseSensitive { get; set; }

        /// <summary>Drop findings scored below this confidence.</summary>
        public double MinConfidence { get; set; }

        /// <summary>Let the learned classifier adjust the confidence of generic detectors.</summary>
        public bool RefineConfidence { get; set; }

        /// <summary>Put raw matched values in findings. Unsafe for logs and reports.</summary>
        public bool IncludeValues { get; set; }

        /// <summary>Cap the UTF-16 length of one scanned string; 0 or less means the default.</summary>
        public int MaxInputLength { get; set; }

        /// <summary>Cap findings per scanned string; 0 or less means the default.</summary>
        public int MaxFindings { get; set; }

        /// <summary>Use another detector pack instead of the bundled one.</summary>
        public Pack? Pack { get; set; }

        internal int EffectiveMaxInputLength => MaxInputLength > 0 ? MaxInputLength : DefaultMaxInputLength;

        internal int EffectiveMaxFindings => MaxFindings > 0 ? MaxFindings : DefaultMaxFindings;

        /// <summary>A copy that shares nothing mutable with this one.</summary>
        public RedactOptions Clone() => new RedactOptions
        {
            Only = new List<string>(Only ?? Array.Empty<string>()),
            Enable = new List<string>(Enable ?? Array.Empty<string>()),
            Disable = new List<string>(Disable ?? Array.Empty<string>()),
            Mode = Mode,
            Mask = Mask,
            MaskFunction = MaskFunction,
            TransformSecret = TransformSecret ?? "",
            RedactKeys = RedactKeys,
            KeyNames = KeyNames == null ? null : new List<string>(KeyNames),
            Allow = new List<string>(Allow ?? Array.Empty<string>()),
            AllowPredicate = AllowPredicate,
            Terms = new List<Term>(Terms ?? Array.Empty<Term>()),
            TermsCaseSensitive = TermsCaseSensitive,
            MinConfidence = MinConfidence,
            RefineConfidence = RefineConfidence,
            IncludeValues = IncludeValues,
            MaxInputLength = MaxInputLength,
            MaxFindings = MaxFindings,
            Pack = Pack,
        };

        /// <summary>Read options from a JSON wire document.</summary>
        /// <exception cref="FormatException">The text is not valid JSON.</exception>
        /// <exception cref="ArgumentException">An unknown option or a wrongly typed value.</exception>
        public static RedactOptions FromJson(string json)
        {
            if (!(Json.Parse(json) is IDictionary<string, object?> payload)) throw new ArgumentException("options must be a JSON object");
            return FromWire(payload);
        }

        /// <summary>Read options from the JSON wire representation, as parsed by <see cref="Json.Parse"/>.</summary>
        /// <param name="payload">The wire options; null means the defaults.</param>
        /// <exception cref="ArgumentException">An unknown option or a wrongly typed value.</exception>
        public static RedactOptions FromWire(IDictionary<string, object?>? payload)
        {
            var options = new RedactOptions();
            if (payload == null) return options;
            foreach (string key in payload.Keys)
            {
                if (!WireOptionNames.Contains(key)) throw new ArgumentException("unknown option \"" + key + "\"");
            }
            if (payload.TryGetValue("only", out object? only)) options.Only = Strings(only, "only");
            if (payload.TryGetValue("enable", out object? enable)) options.Enable = Strings(enable, "enable");
            if (payload.TryGetValue("disable", out object? disable)) options.Disable = Strings(disable, "disable");
            if (payload.TryGetValue("allow", out object? allow)) options.Allow = Strings(allow, "allow");
            if (Pack.Get(payload, "mode") is string mode) options.Mode = WireNames.ParseMode(mode);
            if (Pack.Get(payload, "mask") is string mask) options.Mask = mask;
            if (Pack.Get(payload, "transformSecret") is string secret) options.TransformSecret = secret;
            if (payload.TryGetValue("redactKeys", out object? redactKeys))
            {
                if (redactKeys is bool flag)
                {
                    options.RedactKeys = flag;
                }
                else
                {
                    options.RedactKeys = true;
                    options.KeyNames = Strings(redactKeys, "redactKeys");
                }
            }
            if (payload.TryGetValue("terms", out object? terms)) options.Terms = WireTerms(terms);
            if (Pack.Get(payload, "termsCaseSensitive") is bool caseSensitive) options.TermsCaseSensitive = caseSensitive;
            object? minConfidence = Pack.Get(payload, "minConfidence");
            if (minConfidence is long || minConfidence is double) options.MinConfidence = Pack.Number(minConfidence, 0);
            if (Pack.Get(payload, "refineConfidence") is bool refine) options.RefineConfidence = refine;
            if (Pack.Get(payload, "includeValues") is bool includeValues) options.IncludeValues = includeValues;
            if (Pack.Get(payload, "limits") is IDictionary<string, object?> limits)
            {
                object? maxInputLength = Pack.Get(limits, "maxInputLength");
                if (maxInputLength is long || maxInputLength is double) options.MaxInputLength = Saturate(Pack.Number(maxInputLength, 0));
                object? maxFindings = Pack.Get(limits, "maxFindings");
                if (maxFindings is long || maxFindings is double) options.MaxFindings = Saturate(Pack.Number(maxFindings, 0));
            }
            return options;
        }

        private static int Saturate(double value) =>
            double.IsNaN(value) ? 0 : value >= int.MaxValue ? int.MaxValue : value <= int.MinValue ? int.MinValue : (int)value;

        private static List<string> Strings(object? value, string field)
        {
            if (!(value is IList<object?> items)) throw new ArgumentException("\"" + field + "\" must be an array of strings");
            var output = new List<string>();
            foreach (object? item in items)
            {
                if (!(item is string text)) throw new ArgumentException("\"" + field + "\" must be an array of strings");
                output.Add(text);
            }
            return output;
        }

        private static List<Term> WireTerms(object? value)
        {
            var output = new List<Term>();
            if (value is IList<object?> items)
            {
                foreach (object? item in items)
                {
                    if (item is string text)
                    {
                        output.Add(new Term(text));
                    }
                    else if (item is IDictionary<string, object?> entry)
                    {
                        output.Add(new Term(Pack.Get(entry, "term") as string ?? "", Pack.Get(entry, "replace") as string));
                    }
                    else
                    {
                        throw new ArgumentException("\"terms\" entries must be strings or objects");
                    }
                }
                return output;
            }
            if (value is IDictionary<string, object?> map)
            {
                // A {term: replacement} object, in document order.
                foreach (KeyValuePair<string, object?> entry in map) output.Add(new Term(entry.Key, entry.Value as string));
                return output;
            }
            throw new ArgumentException("\"terms\" must be an array or an object");
        }

        /// <summary>
        /// The wire form of these options, omitting defaults. The transform secret, the mask
        /// function, the allow predicate and a custom pack are not included: the secret stays where
        /// it was configured, and code cannot travel as JSON.
        /// </summary>
        public Dictionary<string, object?> ToWire()
        {
            var wire = new Dictionary<string, object?>(StringComparer.Ordinal);
            if (Only != null && Only.Count > 0) wire["only"] = Only.Cast<object?>().ToList();
            if (Enable != null && Enable.Count > 0) wire["enable"] = Enable.Cast<object?>().ToList();
            if (Disable != null && Disable.Count > 0) wire["disable"] = Disable.Cast<object?>().ToList();
            if (Allow != null && Allow.Count > 0) wire["allow"] = Allow.Cast<object?>().ToList();
            if (Mode != Mode.Mask) wire["mode"] = Mode.WireName();
            if (Mask != null) wire["mask"] = Mask;
            if (!RedactKeys) wire["redactKeys"] = false;
            else if (KeyNames != null) wire["redactKeys"] = KeyNames.Cast<object?>().ToList();
            if (Terms != null && Terms.Count > 0)
            {
                var list = new List<object?>();
                foreach (Term term in Terms)
                {
                    if (term.Replace == null)
                    {
                        list.Add(term.Text);
                    }
                    else
                    {
                        list.Add(new Dictionary<string, object?>(StringComparer.Ordinal) { ["term"] = term.Text, ["replace"] = term.Replace });
                    }
                }
                wire["terms"] = list;
            }
            if (TermsCaseSensitive) wire["termsCaseSensitive"] = true;
            if (MinConfidence > 0) wire["minConfidence"] = MinConfidence;
            if (RefineConfidence) wire["refineConfidence"] = true;
            if (IncludeValues) wire["includeValues"] = true;
            var limits = new Dictionary<string, object?>(StringComparer.Ordinal);
            if (EffectiveMaxInputLength != DefaultMaxInputLength) limits["maxInputLength"] = (long)EffectiveMaxInputLength;
            if (EffectiveMaxFindings != DefaultMaxFindings) limits["maxFindings"] = (long)EffectiveMaxFindings;
            if (limits.Count > 0) wire["limits"] = limits;
            return wire;
        }

        /// <summary><see cref="ToWire"/> as JSON text.</summary>
        public string ToJson() => Json.Stringify(ToWire());
    }
}
