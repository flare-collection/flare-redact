using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>One compiled rule: what it matches, how it is validated, how a match is replaced.</summary>
    public sealed class Detector
    {
        internal Regex? Pattern;
        internal int Capture;
        internal string? Before;
        internal string? After;
        internal Regex? Prefilter;
        internal readonly List<Regex> Reject = new List<Regex>();
        internal readonly List<Func<string, bool>> Validators = new List<Func<string, bool>>();
        internal Func<string, string> Mask = _ => "***";
        internal Regex? ContextPositive;
        internal Regex? ContextNegative;
        internal int ContextWindow = 80;
        internal TermsMatcher? Terms;

        internal Detector(string id, string label, string why, Risk risk, double confidence, bool isDefault,
            IEnumerable<string>? tags = null, int priority = 0, bool refine = false)
        {
            Id = id;
            Label = label;
            Why = why;
            Risk = risk;
            Confidence = confidence;
            IsDefault = isDefault;
            Tags = new ReadOnlyCollection<string>((tags ?? Enumerable.Empty<string>()).ToList());
            Priority = priority;
            Refine = refine;
        }

        /// <summary>The detector reported for a value found under a sensitive field name.</summary>
        internal static readonly Detector SensitiveKey = new Detector(
            "sensitive_key", "Sensitive field", "A value stored under a field name that is sensitive by convention.",
            Risk.Critical, 0.98, true);

        /// <summary>The stable identifier, used in findings and in <see cref="Mode.Label"/> mode.</summary>
        public string Id { get; }

        /// <summary>A human-readable name.</summary>
        public string Label { get; }

        /// <summary>One sentence a reader can act on: what an attacker gains.</summary>
        public string Why { get; }

        /// <summary>The privacy impact.</summary>
        public Risk Risk { get; }

        /// <summary>The base confidence before contextual adjustment.</summary>
        public double Confidence { get; }

        /// <summary>The explicit overlap priority; higher wins.</summary>
        public int Priority { get; }

        /// <summary>Whether the detector runs unless disabled.</summary>
        public bool IsDefault { get; }

        /// <summary>The selectable groups for <c>Enable</c>, <c>Disable</c> and <c>Only</c>.</summary>
        public IReadOnlyList<string> Tags { get; }

        /// <summary>Whether the learned classifier may adjust this detector's confidence.</summary>
        public bool Refine { get; }

        /// <summary>Whether a selector names this detector or one of its tags.</summary>
        public bool MatchesSelector(string selector) =>
            string.Equals(Id, selector, StringComparison.Ordinal) || Tags.Contains(selector, StringComparer.Ordinal);

        private static bool MidPair(string subject, int index) =>
            index > 0 && index < subject.Length && char.IsLowSurrogate(subject[index]) && char.IsHighSurrogate(subject[index - 1]);

        /// <summary>The UTF-16 spans of the captured group of every match in a subject.</summary>
        internal List<(int Start, int End)> Spans(string subject)
        {
            if (Terms != null) return Terms.FindAll(subject);
            var output = new List<(int, int)>();
            Regex pattern = Pattern!;
            int length = subject.Length;
            int from = 0;
            while (from <= length)
            {
                Match match = pattern.Match(subject, from);
                if (!match.Success) break;
                int start = match.Index;
                if (MidPair(subject, start))
                {
                    // .NET may try a match from the middle of a surrogate pair; the reference
                    // engine moves by code point and never does.
                    from = start + 1;
                    continue;
                }
                Group group = match.Groups[Capture];
                output.Add(group.Success ? (group.Index, group.Index + group.Length) : (-1, -1));
                int end = start + match.Length;
                from = end > start ? end : start + 1;
            }
            return output;
        }

        internal bool BoundaryOk(string subject, int start, int end)
        {
            if (Before != null && start > 0 && Before.IndexOf(subject[start - 1]) >= 0) return false;
            return After == null || end >= subject.Length || After.IndexOf(subject[end]) < 0;
        }

        internal bool Rejects(string value)
        {
            foreach (Regex pattern in Reject)
            {
                if (pattern.IsMatch(value)) return true;
            }
            return false;
        }

        internal bool Validates(string value)
        {
            foreach (Func<string, bool> validator in Validators)
            {
                if (!validator(value)) return false;
            }
            return true;
        }

        /// <inheritdoc />
        public override string ToString() => "Detector{" + Id + ", risk=" + Risk.WireName() + ", default=" + IsDefault + "}";
    }
}
