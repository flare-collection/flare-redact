using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace FlareRedact
{
    /// <summary>
    /// Translates an FRS-1 pattern into .NET regular expression syntax.
    /// </summary>
    /// <remarks>
    /// .NET matches UTF-16 code units, while FRS-1 (like JavaScript's <c>u</c> flag)
    /// matches code points. The translation closes that gap: an astral literal becomes its
    /// surrogate pair as one group, a class holding astral code points gains surrogate-pair
    /// alternatives, a negated class and <c>.</c> consume a whole pair or nothing, and
    /// <c>{{L}}</c> includes the astral letters. <c>$</c> is the end of input, <c>\d</c>,
    /// <c>\w</c> and <c>\s</c> keep their JavaScript meaning, and a case-insensitive pattern
    /// has its literals and classes spelled out with their whole case class (see
    /// <see cref="CaseFolding"/>) instead of using <c>RegexOptions.IgnoreCase</c>.
    /// </remarks>
    internal static class PatternTranslator
    {
        private const string Pair = "[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]";
        // The single-unit alternatives refuse the first half of a pair, so backtracking can
        // never split a code point the way JavaScript's u flag never does.
        private const string Any = "(?:" + Pair + "|(?!" + Pair + ")[\\u0000-\\uFFFF])";
        private const string Dot = "(?:" + Pair + "|(?!" + Pair + ")[^\\n\\r\\u2028\\u2029])";
        private const string AsciiWord = "[A-Za-z0-9_]";
        private const string WordBoundary =
            "(?:(?<=" + AsciiWord + ")(?!" + AsciiWord + ")|(?<!" + AsciiWord + ")(?=" + AsciiWord + "))";
        private const string NotWordBoundary =
            "(?:(?<=" + AsciiWord + ")(?=" + AsciiWord + ")|(?<!" + AsciiWord + ")(?!" + AsciiWord + "))";

        private static readonly int[][] DigitRanges = { new[] { 0x30, 0x39 } };
        private static readonly int[][] WordRanges = { new[] { 0x30, 0x39 }, new[] { 0x41, 0x5A }, new[] { 0x5F, 0x5F }, new[] { 0x61, 0x7A } };

        // JavaScript's \s: WhiteSpace and LineTerminator.
        private static readonly int[][] SpaceRanges =
        {
            new[] { 0x09, 0x0D }, new[] { 0x20, 0x20 }, new[] { 0xA0, 0xA0 }, new[] { 0x1680, 0x1680 },
            new[] { 0x2000, 0x200A }, new[] { 0x2028, 0x2029 }, new[] { 0x202F, 0x202F }, new[] { 0x205F, 0x205F },
            new[] { 0x3000, 0x3000 }, new[] { 0xFEFF, 0xFEFF },
        };

        private static string? _letter;

        /// <summary>One parsed element: a literal, a set of ranges, or text copied as it is.</summary>
        private struct Atom
        {
            internal int Code;
            internal int[][]? Ranges;
            internal bool Negated;
            internal string? Opaque;
            internal int Next;
        }

        internal static string Translate(string source, bool insensitive)
        {
            var output = new StringBuilder(source.Length + 16);
            int index = 0;
            while (index < source.Length)
            {
                if (string.CompareOrdinal(source, index, "{{ANY}}", 0, 7) == 0)
                {
                    output.Append(Any);
                    index += 7;
                    continue;
                }
                if (string.CompareOrdinal(source, index, "{{L}}", 0, 5) == 0)
                {
                    output.Append(Letter());
                    index += 5;
                    continue;
                }
                char ch = source[index];
                switch (ch)
                {
                    case '[':
                        index = TranslateClass(source, index, insensitive, output);
                        continue;
                    case '(':
                        index = CopyGroupHeader(source, index, output);
                        continue;
                    case ')':
                    case '|':
                    case '*':
                    case '+':
                    case '?':
                    case '^':
                        output.Append(ch);
                        index++;
                        continue;
                    case '$':
                        output.Append("\\z");
                        index++;
                        continue;
                    case '.':
                        output.Append(Dot);
                        index++;
                        continue;
                    case '{':
                    {
                        int close = QuantifierEnd(source, index);
                        if (close > 0)
                        {
                            output.Append(source, index, close + 1 - index);
                            index = close + 1;
                            continue;
                        }
                        break;
                    }
                }
                if (ch == '\\' && index + 1 < source.Length && (source[index + 1] == 'b' || source[index + 1] == 'B'))
                {
                    output.Append(source[index + 1] == 'b' ? WordBoundary : NotWordBoundary);
                    index += 2;
                    continue;
                }
                Atom atom = ReadAtom(source, index, inClass: false);
                if (atom.Opaque != null)
                {
                    output.Append(atom.Opaque);
                }
                else if (atom.Ranges != null)
                {
                    // Negated or not, the class is closed first: JavaScript's /iu refuses a
                    // code point when its case class meets the set, so the complement of a
                    // closed set is what \W and friends match.
                    var ranges = new List<int[]>(atom.Ranges);
                    if (insensitive) ranges = Close(ranges);
                    output.Append(EmitSet(ranges, new List<string>(), atom.Negated));
                }
                else
                {
                    AppendLiteral(output, atom.Code, insensitive);
                }
                index = atom.Next;
            }
            return output.ToString();
        }

        /// <summary>A literal string as a pattern: every code point as written, or by its case class.</summary>
        internal static string Literal(string text, bool insensitive)
        {
            var output = new StringBuilder(text.Length * 6);
            for (int i = 0; i < text.Length;)
            {
                int code = CodePointAt(text, i);
                AppendLiteral(output, code, insensitive);
                i += code > 0xFFFF ? 2 : 1;
            }
            return output.ToString();
        }

        internal static int CodePointAt(string text, int index)
        {
            char c = text[index];
            if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
            {
                return char.ConvertToUtf32(c, text[index + 1]);
            }
            return c;
        }

        private static int QuantifierEnd(string source, int open)
        {
            int i = open + 1;
            int digits = i;
            while (i < source.Length && source[i] >= '0' && source[i] <= '9') i++;
            if (i == digits) return -1;
            if (i < source.Length && source[i] == ',')
            {
                i++;
                while (i < source.Length && source[i] >= '0' && source[i] <= '9') i++;
            }
            return i < source.Length && source[i] == '}' ? i : -1;
        }

        private static int CopyGroupHeader(string source, int index, StringBuilder output)
        {
            if (string.CompareOrdinal(source, index, "(?", 0, 2) != 0)
            {
                output.Append('(');
                return index + 1;
            }
            foreach (string head in new[] { "(?:", "(?=", "(?!", "(?<=", "(?<!" })
            {
                if (string.CompareOrdinal(source, index, head, 0, head.Length) == 0)
                {
                    output.Append(head);
                    return index + head.Length;
                }
            }
            int nameStart = string.CompareOrdinal(source, index, "(?P<", 0, 4) == 0 ? index + 4
                : string.CompareOrdinal(source, index, "(?<", 0, 3) == 0 ? index + 3 : -1;
            if (nameStart > 0)
            {
                int close = source.IndexOf('>', nameStart);
                int end = close < 0 ? source.Length : close + 1;
                output.Append("(?<").Append(source, nameStart, end - nameStart);
                return end;
            }
            output.Append("(?");
            return index + 2;
        }

        private static Atom ReadAtom(string source, int index, bool inClass)
        {
            char ch = source[index];
            if (ch != '\\')
            {
                int code = CodePointAt(source, index);
                return new Atom { Code = code, Next = index + (code > 0xFFFF ? 2 : 1) };
            }
            if (index + 1 >= source.Length) return new Atom { Code = '\\', Next = index + 1 };
            char esc = source[index + 1];
            switch (esc)
            {
                case 't': return new Atom { Code = '\t', Next = index + 2 };
                case 'n': return new Atom { Code = '\n', Next = index + 2 };
                case 'r': return new Atom { Code = '\r', Next = index + 2 };
                case 'f': return new Atom { Code = '\f', Next = index + 2 };
                case 'v': return new Atom { Code = 0x0B, Next = index + 2 };
                case '0': return new Atom { Code = 0, Next = index + 2 };
                case 'b' when inClass: return new Atom { Code = 0x08, Next = index + 2 };
                case 'd': return new Atom { Ranges = DigitRanges, Next = index + 2 };
                case 'D': return new Atom { Ranges = DigitRanges, Negated = true, Next = index + 2 };
                case 'w': return new Atom { Ranges = WordRanges, Next = index + 2 };
                case 'W': return new Atom { Ranges = WordRanges, Negated = true, Next = index + 2 };
                case 's': return new Atom { Ranges = SpaceRanges, Next = index + 2 };
                case 'S': return new Atom { Ranges = SpaceRanges, Negated = true, Next = index + 2 };
                case 'x':
                    if (index + 4 <= source.Length && IsHex(source[index + 2]) && IsHex(source[index + 3]))
                    {
                        return new Atom
                        {
                            Code = int.Parse(source.Substring(index + 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                            Next = index + 4,
                        };
                    }
                    break;
                case 'u':
                {
                    if (index + 2 < source.Length && source[index + 2] == '{')
                    {
                        int close = source.IndexOf('}', index + 3);
                        if (close > index + 3 && int.TryParse(source.Substring(index + 3, close - index - 3),
                                NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int braced) && braced <= 0x10FFFF)
                        {
                            return new Atom { Code = braced, Next = close + 1 };
                        }
                        break;
                    }
                    int unit = Json.Hex4(source, index + 2);
                    if (unit < 0) break;
                    // 😀 is one code point, as with JavaScript's u flag.
                    if (unit >= 0xD800 && unit <= 0xDBFF && index + 12 <= source.Length
                        && source[index + 6] == '\\' && source[index + 7] == 'u')
                    {
                        int low = Json.Hex4(source, index + 8);
                        if (low >= 0xDC00 && low <= 0xDFFF)
                        {
                            return new Atom { Code = char.ConvertToUtf32((char)unit, (char)low), Next = index + 12 };
                        }
                    }
                    return new Atom { Code = unit, Next = index + 6 };
                }
                case 'p':
                case 'P':
                    if (index + 2 < source.Length && source[index + 2] == '{')
                    {
                        int close = source.IndexOf('}', index + 3);
                        if (close >= 0)
                        {
                            string name = source.Substring(index + 3, close - index - 3);
                            if (esc == 'p' && name == "L" && !inClass)
                            {
                                return new Atom { Opaque = Letter(), Next = close + 1 };
                            }
                            return new Atom { Opaque = source.Substring(index, close + 1 - index), Next = close + 1 };
                        }
                    }
                    break;
                case 'k':
                    if (index + 2 < source.Length && source[index + 2] == '<')
                    {
                        int close = source.IndexOf('>', index + 3);
                        if (close >= 0) return new Atom { Opaque = source.Substring(index, close + 1 - index), Next = close + 1 };
                    }
                    break;
            }
            if ((esc >= 'A' && esc <= 'Z') || (esc >= 'a' && esc <= 'z') || (esc >= '0' && esc <= '9'))
            {
                return new Atom { Opaque = source.Substring(index, 2), Next = index + 2 };
            }
            int literal = CodePointAt(source, index + 1);
            return new Atom { Code = literal, Next = index + 1 + (literal > 0xFFFF ? 2 : 1) };
        }

        private static bool IsHex(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

        private static void AppendLiteral(StringBuilder output, int code, bool insensitive)
        {
            int[]? orbit = insensitive ? CaseFolding.Orbit(code) : null;
            if (orbit == null)
            {
                AppendCode(output, code);
                return;
            }
            var ranges = new List<int[]>();
            foreach (int member in orbit) ranges.Add(new[] { member, member });
            output.Append(EmitSet(ranges, new List<string>(), false));
        }

        private static void AppendCode(StringBuilder output, int code)
        {
            if ((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') || (code >= '0' && code <= '9'))
            {
                output.Append((char)code);
            }
            else if (code > 0xFFFF)
            {
                string pair = char.ConvertFromUtf32(code);
                output.Append("(?:").Append(Unit(pair[0])).Append(Unit(pair[1])).Append(')');
            }
            else if (code >= 0xD800 && code <= 0xDBFF)
            {
                // A lone high surrogate in the pattern matches only a lone one in the text.
                output.Append("(?:").Append(Unit(code)).Append("(?![\\uDC00-\\uDFFF]))");
            }
            else
            {
                output.Append(Unit(code));
            }
        }

        private static string Unit(int code) => "\\u" + code.ToString("X4", CultureInfo.InvariantCulture);

        private static int TranslateClass(string source, int start, bool insensitive, StringBuilder output)
        {
            int index = start + 1;
            bool negated = false;
            if (index < source.Length && source[index] == '^')
            {
                negated = true;
                index++;
            }
            var ranges = new List<int[]>();
            var opaque = new List<string>();
            bool first = true;
            while (index < source.Length && (source[index] != ']' || first))
            {
                first = false;
                Atom low = ReadAtom(source, index, inClass: true);
                index = low.Next;
                if (index + 1 < source.Length && source[index] == '-' && source[index + 1] != ']')
                {
                    Atom high = ReadAtom(source, index + 1, inClass: true);
                    index = high.Next;
                    if (IsSingle(low) && IsSingle(high))
                    {
                        ranges.Add(new[] { low.Code, high.Code });
                    }
                    else
                    {
                        AddAtom(low, ranges, opaque, insensitive);
                        ranges.Add(new[] { (int)'-', (int)'-' });
                        AddAtom(high, ranges, opaque, insensitive);
                    }
                }
                else
                {
                    AddAtom(low, ranges, opaque, insensitive);
                }
            }
            if (index >= source.Length) throw new ArgumentException("unterminated character class");
            index++;
            if (insensitive) ranges = Close(ranges);
            output.Append(EmitSet(ranges, opaque, negated));
            return index;
        }

        private static bool IsSingle(Atom atom) => atom.Opaque == null && atom.Ranges == null;

        private static void AddAtom(Atom atom, List<int[]> ranges, List<string> opaque, bool insensitive)
        {
            if (atom.Opaque != null)
            {
                opaque.Add(atom.Opaque);
            }
            else if (atom.Ranges != null && atom.Negated)
            {
                var set = new List<int[]>(atom.Ranges);
                ranges.AddRange(Complement(insensitive ? Close(set) : set));
            }
            else if (atom.Ranges != null)
            {
                ranges.AddRange(atom.Ranges);
            }
            else
            {
                ranges.Add(new[] { atom.Code, atom.Code });
            }
        }

        private static List<int[]> Complement(List<int[]> ranges)
        {
            var output = new List<int[]>();
            int next = 0;
            foreach (int[] range in Merge(ranges))
            {
                if (range[0] > next) output.Add(new[] { next, range[0] - 1 });
                next = range[1] + 1;
            }
            if (next <= 0x10FFFF) output.Add(new[] { next, 0x10FFFF });
            return output;
        }

        /// <summary>The ranges with every case class member of their code points added.</summary>
        private static List<int[]> Close(List<int[]> ranges)
        {
            var extra = new SortedSet<int>();
            foreach (int[] range in ranges) CaseFolding.CloseRange(range[0], range[1], extra);
            var output = new List<int[]>(ranges);
            foreach (int code in extra) output.Add(new[] { code, code });
            return output;
        }

        private static List<int[]> Merge(IEnumerable<int[]> ranges)
        {
            var sorted = new List<int[]>();
            foreach (int[] range in ranges) sorted.Add(new[] { Math.Min(range[0], range[1]), Math.Max(range[0], range[1]) });
            sorted.Sort((a, b) => a[0].CompareTo(b[0]));
            var merged = new List<int[]>();
            foreach (int[] range in sorted)
            {
                if (merged.Count > 0 && range[0] <= merged[merged.Count - 1][1] + 1)
                {
                    merged[merged.Count - 1][1] = Math.Max(merged[merged.Count - 1][1], range[1]);
                }
                else
                {
                    merged.Add(range);
                }
            }
            return merged;
        }

        /// <summary>
        /// A set of code points as .NET syntax that matches exactly one code point of the set
        /// (or, negated, one code point outside it), a surrogate pair counting as one.
        /// </summary>
        private static string EmitSet(List<int[]> ranges, List<string> opaque, bool negated)
        {
            var bmp = new StringBuilder();
            var astral = new List<int[]>();
            bool highSurrogates = false;
            foreach (int[] range in Merge(ranges))
            {
                if (range[0] <= 0xFFFF)
                {
                    int high = Math.Min(range[1], 0xFFFF);
                    bmp.Append(Unit(range[0]));
                    if (high != range[0]) bmp.Append('-').Append(Unit(high));
                    if (range[0] <= 0xDBFF && high >= 0xD800) highSurrogates = true;
                }
                if (range[1] > 0xFFFF) astral.Add(new[] { Math.Max(range[0], 0x10000), range[1] });
            }
            foreach (string escape in opaque) bmp.Append(escape);
            // An escape such as \P{L} may take surrogates one at a time.
            if (opaque.Count > 0) highSurrogates = true;
            List<string> pairs = SurrogateAlternatives(astral);

            if (negated)
            {
                string single = bmp.Length == 0 ? "[\\u0000-\\uFFFF]" : "[^" + bmp + "]";
                string pair = pairs.Count == 0 ? Pair : "(?!" + Join(pairs) + ")" + Pair;
                return "(?:(?!" + Pair + ")" + single + "|" + pair + ")";
            }
            var parts = new List<string>();
            if (bmp.Length > 0)
            {
                // A class holding high surrogates must not take the first half of a pair.
                parts.Add((highSurrogates ? "(?!" + Pair + ")" : "") + "[" + bmp + "]");
            }
            parts.AddRange(pairs);
            if (parts.Count == 0) return "(?!)";
            if (parts.Count == 1 && bmp.Length > 0 && !highSurrogates) return parts[0];
            return Join(parts);
        }

        private static string Join(List<string> parts) => "(?:" + string.Join("|", parts) + ")";

        private static List<string> SurrogateAlternatives(List<int[]> astral)
        {
            var output = new List<string>();
            foreach (int[] range in Merge(astral))
            {
                string low = char.ConvertFromUtf32(range[0]);
                string high = char.ConvertFromUtf32(range[1]);
                if (low[0] == high[0])
                {
                    output.Add(Unit(low[0]) + Span(low[1], high[1]));
                    continue;
                }
                output.Add(Unit(low[0]) + Span(low[1], 0xDFFF));
                if (high[0] - low[0] > 1)
                {
                    output.Add(Span(low[0] + 1, high[0] - 1) + "[\\uDC00-\\uDFFF]");
                }
                output.Add(Unit(high[0]) + Span(0xDC00, high[1]));
            }
            return output;
        }

        private static string Span(int from, int to) =>
            from == to ? Unit(from) : "[" + Unit(from) + "-" + Unit(to) + "]";

        /// <summary><c>\p{L}</c> with its astral members, which .NET's own <c>\p{L}</c> leaves out.</summary>
        internal static string Letter()
        {
            string? cached = _letter;
            if (cached != null) return cached;
            var astral = new List<int[]>();
            int start = -1;
            for (int code = 0x10000; code <= 0x3FFFF; code++)
            {
                bool letter = IsLetter(code);
                if (letter && start < 0) start = code;
                if (!letter && start >= 0)
                {
                    astral.Add(new[] { start, code - 1 });
                    start = -1;
                }
            }
            if (start >= 0) astral.Add(new[] { start, 0x3FFFF });
            cached = "(?:\\p{L}|" + string.Join("|", SurrogateAlternatives(astral)) + ")";
            _letter = cached;
            return cached;
        }

        internal static bool IsLetter(int code)
        {
            UnicodeCategory category = Category(code);
            return category == UnicodeCategory.UppercaseLetter || category == UnicodeCategory.LowercaseLetter
                || category == UnicodeCategory.TitlecaseLetter || category == UnicodeCategory.ModifierLetter
                || category == UnicodeCategory.OtherLetter;
        }

        internal static UnicodeCategory Category(int code)
        {
#if NET5_0_OR_GREATER
            return CharUnicodeInfo.GetUnicodeCategory(code);
#else
            return code > 0xFFFF
                ? CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(code), 0)
                : CharUnicodeInfo.GetUnicodeCategory((char)code);
#endif
        }
    }
}
