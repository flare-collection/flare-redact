using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>
    /// The learned secret-confidence classifier (SPEC §6): a 14-feature logistic regression whose
    /// weights ship inside the detector pack. It lets <c>RefineConfidence</c> push benign
    /// look-alikes (a git SHA, a UUID, a digest) below a threshold instead of masking them.
    /// </summary>
    public sealed class ConfidenceModel
    {
        internal static readonly string[] Features =
        {
            "log2Len", "entropy", "fracLower", "fracUpper", "fracDigit", "fracSymbol",
            "fracHex", "vowelFrac", "classTransitionRate", "hasMixedClasses",
            "maxRunFrac", "structuredHexId", "ctxSecret", "ctxBenign",
        };

        // Context words use ASCII-only case folding and ASCII word boundaries, so the patterns
        // are case-sensitive and run over an ASCII-lowered copy.
        private static readonly Regex SecretContext = new Regex(
            "(?<![A-Za-z0-9_])(?:secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer"
            + "|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)(?![A-Za-z0-9_])",
            RegexOptions.CultureInvariant);

        private static readonly Regex BenignContext = new Regex(
            "(?<![A-Za-z0-9_])(?:uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision"
            + "|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id|content[_-]?id"
            + "|version|colou?r|slug|filename)(?![A-Za-z0-9_])",
            RegexOptions.CultureInvariant);

        private static readonly Regex StructuredHex = new Regex(
            "^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24}"
            + "|[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\\z",
            RegexOptions.CultureInvariant);

        private readonly double[] _weights;
        private readonly double _bias;

        internal ConfidenceModel(int version, IList<string> features, double[] weights, double bias)
        {
            if (weights.Length != features.Count)
            {
                throw new PackException("confidence model has " + weights.Length + " weights for "
                    + features.Count + " features");
            }
            if (!features.SequenceEqual(Features, StringComparer.Ordinal))
            {
                throw new PackException("confidence model features [" + string.Join(", ", features)
                    + "] do not match this engine's [" + string.Join(", ", Features) + "]");
            }
            Version = version;
            _weights = (double[])weights.Clone();
            _bias = bias;
        }

        /// <summary>The model version declared by the pack.</summary>
        public int Version { get; }

        private static string AsciiLower(string text)
        {
            char[]? output = null;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c >= 'A' && c <= 'Z')
                {
                    output ??= text.ToCharArray();
                    output[i] = (char)(c + 32);
                }
            }
            return output == null ? text : new string(output);
        }

        private static bool IsVowel(char c) => "aeiouAEIOU".IndexOf(c) >= 0;

        /// <summary>The feature vector for a value, over UTF-16 code units as in JavaScript.</summary>
        internal static double[] FeatureVector(string value, string context)
        {
            int length = Math.Max(1, value.Length);
            int lower = 0, upper = 0, digit = 0, symbol = 0, hex = 0, vowel = 0, letters = 0;
            int transitions = 0, run = 1, maxRun = 1, previous = -1;
            foreach (char c in value)
            {
                if (c >= 'a' && c <= 'z')
                {
                    lower++;
                    letters++;
                }
                else if (c >= 'A' && c <= 'Z')
                {
                    upper++;
                    letters++;
                }
                else if (c >= '0' && c <= '9')
                {
                    digit++;
                }
                else
                {
                    symbol++;
                }
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) hex++;
                if (IsVowel(c)) vowel++;
                int kind = c >= '0' && c <= '9' ? 1 : (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ? 0 : 2;
                if (previous == -1)
                {
                    previous = kind;
                }
                else
                {
                    if (kind != previous)
                    {
                        transitions++;
                        run = 1;
                    }
                    else
                    {
                        run++;
                    }
                    if (run > maxRun) maxRun = run;
                    previous = kind;
                }
            }
            string folded = AsciiLower(context);
            double total = length;
            return new[]
            {
                Checksums.Log2(total),
                Checksums.ShannonEntropy(value),
                lower / total,
                upper / total,
                digit / total,
                symbol / total,
                hex / total,
                letters > 0 ? (double)vowel / letters : 0,
                length > 1 ? (double)transitions / (length - 1) : 0,
                lower > 0 && upper > 0 && digit > 0 ? 1 : 0,
                maxRun / total,
                StructuredHex.IsMatch(value) ? 1 : 0,
                SecretContext.IsMatch(folded) ? 1 : 0,
                BenignContext.IsMatch(folded) ? 1 : 0,
            };
        }

        /// <summary>
        /// The probability in [0, 1] that a value is a real secret rather than a benign
        /// high-entropy look-alike.
        /// </summary>
        /// <param name="value">The matched value.</param>
        /// <param name="context">The text around it, value included.</param>
        public double SecretProbability(string value, string context)
        {
            double[] x = FeatureVector(value, context);
            double z = _bias;
            for (int i = 0; i < _weights.Length; i++) z += _weights[i] * x[i];
            return z >= 0 ? 1 / (1 + Math.Exp(-z)) : Math.Exp(z) / (1 + Math.Exp(z));
        }
    }
}
