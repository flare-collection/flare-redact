using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;

namespace FlareRedact
{
    /// <summary>Privacy impact of a detector, used to resolve overlapping matches (SPEC §5).</summary>
    public enum Risk
    {
        /// <summary>Little consequence on its own.</summary>
        Low,
        /// <summary>Identifying in combination with other data.</summary>
        Medium,
        /// <summary>Identifying or exploitable on its own.</summary>
        High,
        /// <summary>A credential or a value that must never leave the process.</summary>
        Critical,
    }

    /// <summary>How a matched value is replaced (SPEC §7).</summary>
    public enum Mode
    {
        /// <summary>The detector's own mask strategy, such as <c>***</c> or <c>**** 4242</c>.</summary>
        Mask,
        /// <summary><c>[REDACTED:&lt;detector id&gt;]</c>.</summary>
        Label,
        /// <summary><c>&lt;detector id&gt;_&lt;keyed fingerprint&gt;</c>; needs a transform secret.</summary>
        Hash,
        /// <summary>A keyed, shape-preserving substitution; needs a transform secret.</summary>
        Pseudonym,
        /// <summary>A keyed, type-consistent synthetic value; needs a transform secret.</summary>
        Surrogate,
    }

    /// <summary>Wire names of <see cref="Risk"/> and <see cref="Mode"/>.</summary>
    public static class WireNames
    {
        /// <summary>The wire name: <c>low</c>, <c>medium</c>, <c>high</c> or <c>critical</c>.</summary>
        public static string WireName(this Risk risk) => risk switch
        {
            Risk.Low => "low",
            Risk.Medium => "medium",
            Risk.High => "high",
            _ => "critical",
        };

        /// <summary>The wire name, such as <c>mask</c> or <c>pseudonym</c>.</summary>
        public static string WireName(this Mode mode) => mode switch
        {
            Mode.Mask => "mask",
            Mode.Label => "label",
            Mode.Hash => "hash",
            Mode.Pseudonym => "pseudonym",
            _ => "surrogate",
        };

        /// <summary>The mode a wire name names.</summary>
        /// <exception cref="ArgumentException">The name is not a mode.</exception>
        public static Mode ParseMode(string name) => name switch
        {
            "mask" => Mode.Mask,
            "label" => Mode.Label,
            "hash" => Mode.Hash,
            "pseudonym" => Mode.Pseudonym,
            "surrogate" => Mode.Surrogate,
            _ => throw new ArgumentException("unknown mode \"" + name + "\""),
        };

        internal static Risk? ParseRisk(string name) => name switch
        {
            "low" => Risk.Low,
            "medium" => Risk.Medium,
            "high" => Risk.High,
            "critical" => Risk.Critical,
            _ => null,
        };

        internal static double Weight(this Risk risk) => risk switch
        {
            Risk.Low => 1,
            Risk.Medium => 1e3,
            Risk.High => 1e6,
            _ => 1e9,
        };
    }

    /// <summary>A word or phrase of your own to always catch, with an optional replacement (SPEC §9).</summary>
    public sealed class Term
    {
        /// <summary>A term replaced by <c>***</c>, or by <paramref name="replace"/> when given.</summary>
        public Term(string text, string? replace = null)
        {
            Text = text ?? throw new ArgumentNullException(nameof(text));
            Replace = replace;
        }

        /// <summary>The literal to catch.</summary>
        public string Text { get; }

        /// <summary>The replacement, or null for <c>***</c>.</summary>
        public string? Replace { get; }

        /// <summary>A term replaced by <c>***</c>.</summary>
        public static implicit operator Term(string text) => new Term(text);
    }

    /// <summary>Base class of every error this library raises.</summary>
    public class FlareRedactException : Exception
    {
        /// <summary>An error with a message.</summary>
        public FlareRedactException(string message) : base(message)
        {
        }

        /// <summary>An error with a message and its cause.</summary>
        public FlareRedactException(string message, Exception inner) : base(message, inner)
        {
        }
    }

    /// <summary>
    /// A detector pack this engine cannot run exactly as the specification describes.
    /// Loading fails rather than silently weakening a check: failing open is how a redactor leaks.
    /// </summary>
    public sealed class PackException : FlareRedactException
    {
        /// <summary>What is wrong with the pack.</summary>
        public PackException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// A configured limit was exceeded, so nothing was redacted (SPEC §12). Limits fail closed:
    /// a partially redacted result the caller cannot detect is worse than an error.
    /// </summary>
    public sealed class RedactionLimitException : FlareRedactException
    {
        /// <summary>Which limit, and by how much.</summary>
        public RedactionLimitException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// One thing the scanner would redact, and why. Offsets are UTF-16 code units, the unit of
    /// <see cref="string.Length"/>; line and column are one-based. A finding made because of a
    /// field name has no position: start, end, line and column are -1.
    /// </summary>
    public sealed class Finding
    {
        internal Finding(string detector, string label, string why, Risk risk, double confidence,
            int start, int end, int line, int column, string? path, string? value)
        {
            Detector = detector;
            Label = label;
            Why = why;
            Risk = risk;
            Confidence = confidence;
            Start = start;
            End = end;
            Line = line;
            Column = column;
            Path = path;
            Value = value;
        }

        /// <summary>The detector id, such as <c>email</c>.</summary>
        public string Detector { get; }

        /// <summary>A human-readable name.</summary>
        public string Label { get; }

        /// <summary>What an attacker gains from the value.</summary>
        public string Why { get; }

        /// <summary>The privacy impact.</summary>
        public Risk Risk { get; }

        /// <summary>The confidence in [0, 1].</summary>
        public double Confidence { get; }

        /// <summary>The start offset in UTF-16 code units, or -1.</summary>
        public int Start { get; }

        /// <summary>The end offset (exclusive) in UTF-16 code units, or -1.</summary>
        public int End { get; }

        /// <summary>The one-based line, or -1.</summary>
        public int Line { get; }

        /// <summary>The one-based column in UTF-16 code units, or -1.</summary>
        public int Column { get; }

        /// <summary>Where the value sits in a structure, such as <c>user.email</c> or <c>items[2]</c>; null at the top level.</summary>
        public string? Path { get; }

        /// <summary>The matched value, only when <c>IncludeValues</c> is set; otherwise null.</summary>
        public string? Value { get; }

        /// <inheritdoc />
        public override string ToString() =>
            "Finding{detector=" + Detector + ", risk=" + Risk.WireName() + ", confidence="
            + Confidence.ToString(CultureInfo.InvariantCulture)
            + (Start >= 0 ? ", start=" + Start + ", end=" + End : "")
            + (Path == null ? "" : ", path=" + Path) + "}";
    }

    /// <summary>Counts of findings by detector and by risk, with no values: safe to log.</summary>
    public sealed class Summary
    {
        internal Summary(int total, IDictionary<string, int> byDetector, IDictionary<string, int> byRisk)
        {
            Total = total;
            ByDetector = new ReadOnlyDictionary<string, int>(byDetector);
            ByRisk = new ReadOnlyDictionary<string, int>(byRisk);
        }

        /// <summary>The number of findings.</summary>
        public int Total { get; }

        /// <summary>Findings per detector id.</summary>
        public IReadOnlyDictionary<string, int> ByDetector { get; }

        /// <summary>Findings per risk wire name.</summary>
        public IReadOnlyDictionary<string, int> ByRisk { get; }
    }
}
