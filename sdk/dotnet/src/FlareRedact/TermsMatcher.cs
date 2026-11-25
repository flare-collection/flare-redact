using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>
    /// The terms scan of SPEC §9, written out rather than left to a lookbehind, so a letter
    /// outside the BMP counts as a neighbour. A candidate position is one where some term
    /// matches; it is taken when the code point before it is not a word character and, trying
    /// the terms in order, one of them ends before a non-word code point. Otherwise the scan
    /// moves on by one character.
    /// </summary>
    internal sealed class TermsMatcher
    {
        private readonly Regex _any;
        private readonly List<Regex> _each;
        private readonly List<string> _replace;

        private TermsMatcher(Regex any, List<Regex> each, List<string> replace)
        {
            _any = any;
            _each = each;
            _replace = replace;
        }

        private static int CodePointCount(string text)
        {
            int count = 0;
            for (int i = 0; i < text.Length; i++)
            {
                if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1])) i++;
                count++;
            }
            return count;
        }

        internal static Detector? CreateDetector(IEnumerable<Term> terms, bool caseSensitive)
        {
            // Longest first in characters; OrderBy is stable, so ties keep the caller's order.
            List<Term> ordered = terms
                .Where(term => term != null && term.Text.Length > 0)
                .OrderByDescending(term => CodePointCount(term.Text))
                .ToList();
            if (ordered.Count == 0) return null;

            var each = new List<Regex>();
            var replace = new List<string>();
            var alternation = new StringBuilder();
            foreach (Term term in ordered)
            {
                string source = PatternTranslator.Literal(term.Text, !caseSensitive);
                each.Add(new Regex("\\G(?:" + source + ")", RegexOptions.CultureInvariant));
                replace.Add(term.Replace ?? "***");
                if (alternation.Length > 0) alternation.Append('|');
                alternation.Append(source);
            }
            var any = new Regex(alternation.ToString(), RegexOptions.CultureInvariant);
            var matcher = new TermsMatcher(any, each, replace);
            return new Detector("custom_term", "Custom term", "A term you configured as sensitive.", Risk.High, 0.92, true,
                new[] { "custom" })
            {
                Pattern = any,
                Terms = matcher,
                Mask = matcher.ReplacementFor,
            };
        }

        /// <summary>The boundary class of SPEC §9: letters, combining marks, numbers and <c>_</c>.</summary>
        internal static bool IsWord(int code)
        {
            if (code == '_') return true;
            switch (PatternTranslator.Category(code))
            {
                case UnicodeCategory.UppercaseLetter:
                case UnicodeCategory.LowercaseLetter:
                case UnicodeCategory.TitlecaseLetter:
                case UnicodeCategory.ModifierLetter:
                case UnicodeCategory.OtherLetter:
                case UnicodeCategory.NonSpacingMark:
                case UnicodeCategory.EnclosingMark:
                case UnicodeCategory.SpacingCombiningMark:
                case UnicodeCategory.DecimalDigitNumber:
                case UnicodeCategory.LetterNumber:
                case UnicodeCategory.OtherNumber:
                    return true;
                default:
                    return false;
            }
        }

        private static int CodePointBefore(string text, int index)
        {
            char c = text[index - 1];
            if (char.IsLowSurrogate(c) && index >= 2 && char.IsHighSurrogate(text[index - 2]))
            {
                return char.ConvertToUtf32(text[index - 2], c);
            }
            return c;
        }

        internal List<(int Start, int End)> FindAll(string subject)
        {
            var output = new List<(int, int)>();
            int position = 0;
            while (position < subject.Length)
            {
                Match search = _any.Match(subject, position);
                if (!search.Success) break;
                int start = search.Index;
                int width = PatternTranslator.CodePointAt(subject, start) > 0xFFFF ? 2 : 1;
                if (start > 0 && IsWord(CodePointBefore(subject, start)))
                {
                    position = start + width;
                    continue;
                }
                int end = -1;
                foreach (Regex term in _each)
                {
                    Match m = term.Match(subject, start);
                    if (!m.Success || m.Length == 0) continue;
                    int candidate = start + m.Length;
                    if (candidate < subject.Length && IsWord(PatternTranslator.CodePointAt(subject, candidate))) continue;
                    end = candidate;
                    break;
                }
                if (end < 0)
                {
                    position = start + width;
                    continue;
                }
                output.Add((start, end));
                position = end;
            }
            return output;
        }

        /// <summary>The replacement of the first term, in matching order, that matches a value exactly.</summary>
        internal string ReplacementFor(string value)
        {
            for (int i = 0; i < _each.Count; i++)
            {
                // A term is one literal, so it can match only one length at a position.
                Match m = _each[i].Match(value, 0);
                if (m.Success && m.Length == value.Length) return _replace[i];
            }
            return "***";
        }
    }
}
