using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
#if NET8_0_OR_GREATER
using System.Text.Json;
using System.Text.Json.Nodes;
#endif

namespace FlareRedact
{
    /// <summary>
    /// One compiled set of options, reusable everywhere and safe to share between threads.
    /// Building it resolves the detector list, the replacement and the key and allow tests once,
    /// so your logs, your HTTP layer and your prompts agree on what "sensitive" means.
    /// </summary>
    /// <remarks>
    /// <para>Overlap resolution is maximum-weight interval scheduling rather than first-match, so a
    /// value two detectors match is masked the same way whatever else is on the line. Limits fail
    /// closed: an oversized input throws <see cref="RedactionLimitException"/> instead of returning
    /// partially redacted text.</para>
    /// <para>Structured values are the shapes a JSON library produces: dictionaries, lists, arrays,
    /// strings and scalars, plus <c>System.Text.Json</c>'s <c>JsonNode</c> and <c>JsonElement</c> on
    /// .NET 8 and later. Dictionary keys are never rewritten; a string stored under a sensitive key
    /// is replaced whole. Anything else (a number, a boolean, your own class) is returned unchanged:
    /// serialise it to JSON and use <see cref="RedactJson"/>.</para>
    /// </remarks>
    public sealed class Policy
    {
        /// <summary>How far the learned model may move a base confidence score, up or down.</summary>
        private const double RefineStrength = 0.4;

        /// <summary>Nesting deeper than this is refused rather than risking the stack.</summary>
        internal const int MaxDepth = 1000;

        private readonly RedactOptions _options;
        private readonly HashSet<string> _allowed;
        private readonly Func<string, bool>? _allowPredicate;
        private readonly Func<string, bool> _matchKey;
        private readonly Func<string, Detector, string> _replace;
        private readonly int _maxInputLength;
        private readonly int _maxFindings;

        private Policy(RedactOptions options)
        {
            _options = options;
            Pack = options.Pack ?? Pack.Core;
            Detectors = new ReadOnlyCollection<Detector>(ResolveDetectors(Pack, options));
            _allowed = new HashSet<string>(options.Allow, StringComparer.Ordinal);
            _allowPredicate = options.AllowPredicate;
            _matchKey = KeyMatcher(options);
            _replace = Replacer(options);
            _maxInputLength = options.EffectiveMaxInputLength;
            _maxFindings = options.EffectiveMaxFindings;
        }

        /// <summary>Compile options into a policy.</summary>
        /// <exception cref="FlareRedactException">A keyed mode has no transform secret.</exception>
        public static Policy Compile(RedactOptions? options = null) => new Policy((options ?? new RedactOptions()).Clone());

        /// <summary>The options this policy was compiled from (a copy).</summary>
        public RedactOptions Options => _options.Clone();

        /// <summary>The detector pack in use.</summary>
        public Pack Pack { get; }

        /// <summary>The resolved detectors, in evaluation order.</summary>
        public IReadOnlyList<Detector> Detectors { get; }

        private static List<Detector> ResolveDetectors(Pack pack, RedactOptions options)
        {
            var chosen = new List<Detector>();
            foreach (Detector detector in pack.Detectors)
            {
                if (options.Only.Count > 0)
                {
                    if (MatchesAny(detector, options.Only)) chosen.Add(detector);
                    continue;
                }
                if ((detector.IsDefault || MatchesAny(detector, options.Enable)) && !MatchesAny(detector, options.Disable))
                {
                    chosen.Add(detector);
                }
            }
            Detector? terms = TermsMatcher.CreateDetector(options.Terms, options.TermsCaseSensitive);
            if (terms != null) chosen.Insert(0, terms);
            return chosen;
        }

        private static bool MatchesAny(Detector detector, IList<string> selectors)
        {
            foreach (string selector in selectors)
            {
                if (detector.MatchesSelector(selector)) return true;
            }
            return false;
        }

        private static Func<string, bool> KeyMatcher(RedactOptions options)
        {
            if (!options.RedactKeys) return _ => false;
            if (options.KeyNames != null)
            {
                var names = new HashSet<string>(options.KeyNames.Select(Keywords.NormalizeKeyName), StringComparer.Ordinal);
                return key => names.Contains(Keywords.NormalizeKeyName(key));
            }
            return Keywords.IsSensitiveKeyName;
        }

        private static Func<string, Detector, string> Replacer(RedactOptions options)
        {
            if (options.MaskFunction != null) return options.MaskFunction;
            if (options.Mask != null)
            {
                string mask = options.Mask;
                return (_, _) => mask;
            }
            string secret = options.TransformSecret;
            switch (options.Mode)
            {
                case Mode.Label:
                    return (_, detector) => "[REDACTED:" + detector.Id + "]";
                case Mode.Hash:
                    Transforms.RequireSecret(secret);
                    return (value, detector) => detector.Id + "_" + Transforms.HmacFingerprint(secret, value, 16);
                case Mode.Pseudonym:
                    Transforms.RequireSecret(secret);
                    return (value, _) => Transforms.Pseudonymize(value, secret);
                case Mode.Surrogate:
                    Transforms.RequireSecret(secret);
                    return (value, detector) => Transforms.Surrogate(value, detector.Id, secret);
                default:
                    return (value, detector) => detector.Mask(value);
            }
        }

        internal bool Allows(string value) => _allowed.Contains(value) || (_allowPredicate != null && _allowPredicate(value));

        internal bool IsSensitiveKey(string key) => _matchKey(key);

        // -------------------------------------------------------------------
        // Scanning
        // -------------------------------------------------------------------

        /// <summary>One accepted match: UTF-16 offsets into the original string.</summary>
        internal sealed class Hit
        {
            internal readonly Detector Detector;
            internal readonly int Start;
            internal readonly int End;
            internal readonly string Value;
            internal readonly double Confidence;
            internal readonly double Weight;

            internal Hit(Detector detector, int start, int end, string value, double confidence)
            {
                Detector = detector;
                Start = start;
                End = end;
                Value = value;
                Confidence = confidence;
                Weight = detector.Risk.Weight() + 10.0 * detector.Priority + confidence + (end - start) / 1_000_000.0;
            }
        }

        private static bool IsZeroWidth(char c) => c == '​' || c == '‌' || c == '‍' || c == '⁠' || c == '﻿';

        /// <summary>
        /// The scan of SPEC §4 and §5. Invisible characters an attacker can splice through a
        /// secret are stripped before matching, keeping a map from each unit of the stripped text
        /// back to the original, so the replacement covers the splice too.
        /// </summary>
        internal List<Hit> ScanHits(string text)
        {
            if (text.Length > _maxInputLength)
            {
                throw new RedactionLimitException("input length " + text.Length + " exceeds the configured limit of " + _maxInputLength);
            }
            string subject = text;
            int[]? source = null;
            for (int i = 0; i < text.Length; i++)
            {
                if (!IsZeroWidth(text[i])) continue;
                var stripped = new StringBuilder(text.Length);
                var map = new int[text.Length];
                int n = 0;
                for (int j = 0; j < text.Length; j++)
                {
                    if (IsZeroWidth(text[j])) continue;
                    stripped.Append(text[j]);
                    map[n++] = j;
                }
                subject = stripped.ToString();
                source = map;
                break;
            }

            var hits = new List<Hit>();
            foreach (Detector detector in Detectors) ScanDetector(detector, text, subject, source, hits);
            return hits.Count < 2 ? hits : SelectNonOverlapping(hits);
        }

        private void ScanDetector(Detector detector, string text, string subject, int[]? source, List<Hit> hits)
        {
            if (detector.Prefilter != null && !detector.Prefilter.IsMatch(subject)) return;
            foreach ((int ns, int ne) in detector.Spans(subject))
            {
                if (ns < 0 || ne <= ns) continue;
                if (!detector.BoundaryOk(subject, ns, ne)) continue;
                string normalized = subject.Substring(ns, ne - ns);
                if (detector.Rejects(normalized) || !detector.Validates(normalized)) continue;
                int start = ns;
                int end = ne;
                if (source != null)
                {
                    start = source[ns];
                    end = source[ne - 1] + 1;
                }
                string value = text.Substring(start, end - start);
                if (Allows(value) || (!string.Equals(value, normalized, StringComparison.Ordinal) && Allows(normalized))) continue;
                double confidence = ScoreConfidence(detector, text, start, end);
                if (confidence < _options.MinConfidence) continue;
                hits.Add(new Hit(detector, start, end, value, confidence));
                if (hits.Count > _maxFindings)
                {
                    throw new RedactionLimitException("finding count exceeds the configured limit of " + _maxFindings);
                }
            }
        }

        private double ScoreConfidence(Detector detector, string text, int start, int end)
        {
            double score = detector.Confidence;
            if (detector.ContextPositive != null || detector.ContextNegative != null)
            {
                int radius = detector.ContextWindow;
                int from = Math.Max(0, start - radius);
                string nearby = text.Substring(from, Math.Min(text.Length, end + radius) - from);
                if (detector.ContextPositive != null && detector.ContextPositive.IsMatch(nearby)) score += 0.06;
                if (detector.ContextNegative != null && detector.ContextNegative.IsMatch(nearby)) score -= 0.25;
            }
            ConfidenceModel? model = Pack.Model;
            if (_options.RefineConfidence && detector.Refine && model != null)
            {
                int from = Math.Max(0, start - 64);
                string window = text.Substring(from, Math.Min(text.Length, end + 64) - from);
                score += (model.SecretProbability(text.Substring(start, end - start), window) - 0.5) * RefineStrength;
            }
            return Math.Max(0, Math.Min(1, score));
        }

        /// <summary>
        /// Keep the maximum-weight set of non-overlapping spans. First-match-wins would make masking
        /// depend on detector order.
        /// </summary>
        private static List<Hit> SelectNonOverlapping(List<Hit> hits)
        {
            // OrderBy is stable, as Java's and JavaScript's sorts are.
            List<Hit> sorted = hits.OrderBy(h => h.End).ThenBy(h => h.Start).ToList();
            int count = sorted.Count;
            var previous = new int[count];
            for (int i = 0; i < count; i++)
            {
                int low = 0;
                int high = i - 1;
                int found = -1;
                while (low <= high)
                {
                    int mid = (low + high) >> 1;
                    if (sorted[mid].End <= sorted[i].Start)
                    {
                        found = mid;
                        low = mid + 1;
                    }
                    else
                    {
                        high = mid - 1;
                    }
                }
                previous[i] = found;
            }
            var best = new double[count + 1];
            for (int i = 1; i <= count; i++)
            {
                double include = sorted[i - 1].Weight + best[previous[i - 1] + 1];
                best[i] = Math.Max(best[i - 1], include);
            }
            var selected = new List<Hit>();
            for (int i = count; i > 0;)
            {
                Hit hit = sorted[i - 1];
                double include = hit.Weight + best[previous[i - 1] + 1];
                if (include > best[i - 1])
                {
                    selected.Add(hit);
                    i = previous[i - 1] + 1;
                }
                else
                {
                    i--;
                }
            }
            selected.Reverse();
            return selected.OrderBy(h => h.Start).ThenBy(h => h.End).ToList();
        }

        internal string Rewrite(string text, Func<Hit, string> replacement)
        {
            List<Hit> hits = ScanHits(text);
            if (hits.Count == 0) return text;
            var output = new StringBuilder(text.Length + 16);
            int cursor = 0;
            foreach (Hit hit in hits)
            {
                output.Append(text, cursor, hit.Start - cursor);
                output.Append(replacement(hit));
                cursor = hit.End;
            }
            return output.Append(text, cursor, text.Length - cursor).ToString();
        }

        /// <summary>
        /// Rewrite one string in a single pass. Replacements are never rescanned, so a mask can
        /// never itself be masked.
        /// </summary>
        /// <exception cref="RedactionLimitException">A configured limit was exceeded.</exception>
        public string RedactString(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            return Rewrite(text, hit => _replace(hit.Value, hit.Detector));
        }

        /// <summary>List what would be redacted in one string, and why, ordered by position.</summary>
        /// <exception cref="RedactionLimitException">A configured limit was exceeded.</exception>
        public IReadOnlyList<Finding> ScanString(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            var output = new List<Finding>();
            ScanStringInto(text, null, output);
            return output;
        }

        private void ScanStringInto(string text, string? path, List<Finding> output)
        {
            int cursor = 0;
            int line = 1;
            int lineStart = 0;
            foreach (Hit hit in ScanHits(text))
            {
                while (cursor < hit.Start)
                {
                    if (text[cursor] == '\n')
                    {
                        line++;
                        lineStart = cursor + 1;
                    }
                    cursor++;
                }
                Detector d = hit.Detector;
                output.Add(new Finding(d.Id, d.Label, d.Why, d.Risk, hit.Confidence, hit.Start, hit.End, line,
                    hit.Start - lineStart + 1, path, _options.IncludeValues ? hit.Value : null));
            }
        }

        // -------------------------------------------------------------------
        // Structured values
        // -------------------------------------------------------------------

        /// <summary>
        /// Redact a string stored under a field name: replaced whole when the name is sensitive by
        /// convention (or in <see cref="RedactOptions.KeyNames"/>), otherwise scanned like any text.
        /// This is the rule <see cref="Redact"/> applies to every string in a dictionary, for
        /// integrations that see fields one at a time, such as logging properties.
        /// </summary>
        public string RedactField(string key, string value)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (value == null) throw new ArgumentNullException(nameof(value));
            return _matchKey(key) && !Allows(value) ? _replace(value, Detector.SensitiveKey) : RedactString(value);
        }

        /// <summary>
        /// Rewrite every string reachable from a value, preserving its shape. Dictionaries come
        /// back as <see cref="Dictionary{TKey, TValue}"/> in the input's order, lists and other
        /// sequences as <see cref="List{T}"/>, arrays as arrays; a cycle in the input is a cycle in
        /// the output.
        /// </summary>
        public object? Redact(object? value) => new Walker(RedactString, RedactField).Walk(value, 0);

        /// <summary>
        /// Redact a JSON document and return a JSON document: the entry point for your own classes
        /// (serialise, redact, deserialise).
        /// </summary>
        /// <exception cref="FormatException">The text is not valid JSON.</exception>
        public string RedactJson(string json) => Json.Stringify(Redact(Json.Parse(json)));

        /// <summary>Compares references, for cycle detection on every target framework.</summary>
        internal sealed class ReferenceComparer : IEqualityComparer<object>
        {
            internal static readonly ReferenceComparer Instance = new ReferenceComparer();

            public new bool Equals(object? x, object? y) => ReferenceEquals(x, y);

            public int GetHashCode(object obj) => RuntimeHelpers.GetHashCode(obj);
        }

        /// <summary>Rebuilds a structured value, transforming every string in it.</summary>
        internal sealed class Walker
        {
            private readonly Func<string, string> _onString;
            private readonly Func<string, string, string>? _onField;
            private readonly Dictionary<object, object> _seen = new Dictionary<object, object>(ReferenceComparer.Instance);

            internal Walker(Func<string, string> onString, Func<string, string, string>? onField)
            {
                _onString = onString;
                _onField = onField;
            }

            internal object? Walk(object? value, int depth)
            {
                switch (value)
                {
                    case null:
                        return null;
                    case string text:
                        return _onString(text);
                }
                if (depth > MaxDepth) throw new FlareRedactException("value nests deeper than " + MaxDepth + " levels");
#if NET8_0_OR_GREATER
                // System.Text.Json values go through the JSON model and come back as the same kind.
                if (value is JsonNode node)
                {
                    return JsonNode.Parse(Json.Stringify(Walk(Json.Parse(node.ToJsonString()), depth)));
                }
                if (value is JsonElement element)
                {
                    using JsonDocument document = JsonDocument.Parse(Json.Stringify(Walk(Json.Parse(element.GetRawText()), depth)));
                    return document.RootElement.Clone();
                }
#endif
                if (value.GetType().IsValueType) return value;
                if (_seen.TryGetValue(value, out object? cached)) return cached;
                switch (value)
                {
                    case IDictionary map:
                        return WalkMap(map, depth);
                    case string[] strings:
                    {
                        var output = new string[strings.Length];
                        _seen[value] = output;
                        for (int i = 0; i < strings.Length; i++) output[i] = (string)Walk(strings[i], depth + 1)!;
                        return output;
                    }
                    case object?[] items:
                    {
                        var output = new object?[items.Length];
                        _seen[value] = output;
                        for (int i = 0; i < items.Length; i++) output[i] = Walk(items[i], depth + 1);
                        return output;
                    }
                    case IEnumerable sequence:
                    {
                        var output = new List<object?>();
                        _seen[value] = output;
                        foreach (object? item in sequence) output.Add(Walk(item, depth + 1));
                        return output;
                    }
                    default:
                        return value;
                }
            }

            private object WalkMap(IDictionary map, int depth)
            {
                bool stringKeys = true;
                foreach (object key in map.Keys)
                {
                    if (!(key is string))
                    {
                        stringKeys = false;
                        break;
                    }
                }
                IDictionary output = stringKeys
                    ? new Dictionary<string, object?>(StringComparer.Ordinal)
                    : (IDictionary)new Dictionary<object, object?>();
                _seen[map] = output;
                foreach (DictionaryEntry entry in map)
                {
                    if (entry.Key is string key && entry.Value is string text && _onField != null)
                    {
                        output[entry.Key] = _onField(key, text);
                    }
                    else
                    {
                        output[entry.Key] = Walk(entry.Value, depth + 1);
                    }
                }
                return output;
            }
        }

        /// <summary>
        /// List what would be redacted anywhere in a value, with paths such as <c>user.email</c> or
        /// <c>items[2]</c>.
        /// </summary>
        public IReadOnlyList<Finding> Scan(object? value)
        {
            var output = new List<Finding>();
            ScanValue(value, "", 0, output, new HashSet<object>(ReferenceComparer.Instance));
            return output;
        }

        private void ScanValue(object? value, string path, int depth, List<Finding> output, HashSet<object> seen)
        {
            if (value == null) return;
            if (value is string text)
            {
                ScanStringInto(text, path.Length == 0 ? null : path, output);
                return;
            }
            if (depth > MaxDepth) throw new FlareRedactException("value nests deeper than " + MaxDepth + " levels");
#if NET8_0_OR_GREATER
            if (value is JsonNode node)
            {
                ScanValue(Json.Parse(node.ToJsonString()), path, depth, output, seen);
                return;
            }
            if (value is JsonElement element)
            {
                ScanValue(Json.Parse(element.GetRawText()), path, depth, output, seen);
                return;
            }
#endif
            if (value.GetType().IsValueType) return;
            switch (value)
            {
                case IDictionary map:
                    if (!seen.Add(value)) return;
                    foreach (DictionaryEntry entry in map)
                    {
                        string name = Convert.ToString(entry.Key, CultureInfo.InvariantCulture) ?? "";
                        string child = path.Length == 0 ? name : path + "." + name;
                        if (entry.Key is string key && entry.Value is string item && _matchKey(key) && !Allows(item))
                        {
                            Detector d = Detector.SensitiveKey;
                            output.Add(new Finding(d.Id, d.Label, "Value stored under a sensitive field name (\"" + key + "\").",
                                Risk.Critical, 0.98, -1, -1, -1, -1, child, _options.IncludeValues ? item : null));
                        }
                        else
                        {
                            ScanValue(entry.Value, child, depth + 1, output, seen);
                        }
                    }
                    return;
                case IEnumerable sequence:
                    if (!seen.Add(value)) return;
                    int index = 0;
                    foreach (object? item in sequence)
                    {
                        ScanValue(item, path + "[" + index.ToString(CultureInfo.InvariantCulture) + "]", depth + 1, output, seen);
                        index++;
                    }
                    return;
            }
        }

        /// <summary>Whether nothing in a value would be redacted.</summary>
        public bool IsClean(object? value) => Scan(value).Count == 0;

        /// <summary>Count findings by detector and by risk. The result holds no matched values and is safe to log.</summary>
        public Summary Summarize(object? value)
        {
            IReadOnlyList<Finding> findings = Scan(value);
            var byDetector = new Dictionary<string, int>(StringComparer.Ordinal);
            var byRisk = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (Finding finding in findings)
            {
                byDetector[finding.Detector] = byDetector.TryGetValue(finding.Detector, out int a) ? a + 1 : 1;
                string risk = finding.Risk.WireName();
                byRisk[risk] = byRisk.TryGetValue(risk, out int b) ? b + 1 : 1;
            }
            return new Summary(findings.Count, byDetector, byRisk);
        }

        /// <summary>A new reversible redactor sharing this policy, with opaque placeholders unless told otherwise.</summary>
        public Vault CreateVault(VaultOptions? vaultOptions = null) => new Vault(this, vaultOptions ?? VaultOptions.Default);
    }
}
