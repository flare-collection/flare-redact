using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace FlareRedact
{
    /// <summary>
    /// A small, strict JSON reader and writer (RFC 8259), so the library needs no
    /// dependency to load a detector pack, read wire options or restore into JSON text.
    /// </summary>
    /// <remarks>
    /// Objects read as <see cref="Dictionary{TKey, TValue}"/> of string to object (member
    /// order kept), arrays as <see cref="List{T}"/>, numbers as <see cref="long"/> when they
    /// are integers that fit and <see cref="double"/> otherwise, and true, false and null as
    /// themselves. Strings may hold lone surrogates written as <c>\uXXXX</c> escapes, as
    /// JavaScript's <c>JSON.parse</c> allows.
    /// </remarks>
    public static class Json
    {
        /// <summary>Nesting deeper than this is refused rather than risking the stack.</summary>
        public const int MaxDepth = 1000;

        /// <summary>Parse a complete JSON document.</summary>
        /// <param name="text">The document.</param>
        /// <returns>The value it denotes.</returns>
        /// <exception cref="FormatException">The text is not valid JSON.</exception>
        public static object? Parse(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            var reader = new Reader(text);
            reader.SkipWhitespace();
            object? value = reader.ReadValue(0);
            reader.SkipWhitespace();
            if (reader.Index != text.Length) throw reader.Error("unexpected content after the document");
            return value;
        }

        /// <summary>
        /// Whether <paramref name="text"/> is a complete, valid JSON document. Never throws,
        /// and checks without building values or recursing.
        /// </summary>
        public static bool IsValid(string text) => text != null && Validator.Valid(text);

        private sealed class Reader
        {
            private readonly string _text;
            internal int Index;

            internal Reader(string text) => _text = text;

            internal FormatException Error(string message) =>
                new FormatException("invalid JSON at offset " + Index.ToString(CultureInfo.InvariantCulture) + ": " + message);

            internal void SkipWhitespace()
            {
                while (Index < _text.Length)
                {
                    char c = _text[Index];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') Index++;
                    else break;
                }
            }

            internal object? ReadValue(int depth)
            {
                if (depth > MaxDepth) throw Error("nesting is deeper than " + MaxDepth);
                if (Index >= _text.Length) throw Error("unexpected end of input");
                char c = _text[Index];
                switch (c)
                {
                    case '{': return ReadObject(depth);
                    case '[': return ReadArray(depth);
                    case '"': return ReadString();
                    case 't': return ReadLiteral("true", true);
                    case 'f': return ReadLiteral("false", false);
                    case 'n': return ReadLiteral("null", null);
                    default:
                        if (c == '-' || (c >= '0' && c <= '9')) return ReadNumber();
                        throw Error("unexpected character");
                }
            }

            private object? ReadLiteral(string word, object? value)
            {
                if (string.CompareOrdinal(_text, Index, word, 0, word.Length) != 0) throw Error("unexpected character");
                Index += word.Length;
                return value;
            }

            private Dictionary<string, object?> ReadObject(int depth)
            {
                Index++;
                var output = new Dictionary<string, object?>(StringComparer.Ordinal);
                SkipWhitespace();
                if (Index < _text.Length && _text[Index] == '}')
                {
                    Index++;
                    return output;
                }
                while (true)
                {
                    SkipWhitespace();
                    if (Index >= _text.Length || _text[Index] != '"') throw Error("expected a member name");
                    string key = ReadString();
                    SkipWhitespace();
                    if (Index >= _text.Length || _text[Index] != ':') throw Error("expected ':'");
                    Index++;
                    SkipWhitespace();
                    output[key] = ReadValue(depth + 1);
                    SkipWhitespace();
                    if (Index >= _text.Length) throw Error("unterminated object");
                    char c = _text[Index++];
                    if (c == '}') return output;
                    if (c != ',') throw Error("expected ',' or '}'");
                }
            }

            private List<object?> ReadArray(int depth)
            {
                Index++;
                var output = new List<object?>();
                SkipWhitespace();
                if (Index < _text.Length && _text[Index] == ']')
                {
                    Index++;
                    return output;
                }
                while (true)
                {
                    SkipWhitespace();
                    output.Add(ReadValue(depth + 1));
                    SkipWhitespace();
                    if (Index >= _text.Length) throw Error("unterminated array");
                    char c = _text[Index++];
                    if (c == ']') return output;
                    if (c != ',') throw Error("expected ',' or ']'");
                }
            }

            private string ReadString()
            {
                Index++;
                StringBuilder? output = null;
                int start = Index;
                while (true)
                {
                    if (Index >= _text.Length) throw Error("unterminated string");
                    char c = _text[Index];
                    if (c == '"')
                    {
                        string tail = _text.Substring(start, Index - start);
                        Index++;
                        return output == null ? tail : output.Append(tail).ToString();
                    }
                    if (c < 0x20) throw Error("unescaped control character in a string");
                    if (c != '\\')
                    {
                        Index++;
                        continue;
                    }
                    output ??= new StringBuilder();
                    output.Append(_text, start, Index - start);
                    if (Index + 1 >= _text.Length) throw Error("unterminated escape");
                    char escape = _text[Index + 1];
                    Index += 2;
                    switch (escape)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            output.Append(escape);
                            break;
                        case 'b': output.Append('\b'); break;
                        case 'f': output.Append('\f'); break;
                        case 'n': output.Append('\n'); break;
                        case 'r': output.Append('\r'); break;
                        case 't': output.Append('\t'); break;
                        case 'u':
                            int unit = Hex4(_text, Index);
                            if (unit < 0) throw Error("invalid \\u escape");
                            output.Append((char)unit);
                            Index += 4;
                            break;
                        default:
                            throw Error("invalid escape");
                    }
                    start = Index;
                }
            }

            private object ReadNumber()
            {
                int start = Index;
                if (_text[Index] == '-') Index++;
                if (Index >= _text.Length) throw Error("invalid number");
                if (_text[Index] == '0') Index++;
                else if (_text[Index] >= '1' && _text[Index] <= '9')
                {
                    while (Index < _text.Length && IsDigit(_text[Index])) Index++;
                }
                else throw Error("invalid number");
                bool integral = true;
                if (Index < _text.Length && _text[Index] == '.')
                {
                    integral = false;
                    Index++;
                    int digits = Index;
                    while (Index < _text.Length && IsDigit(_text[Index])) Index++;
                    if (Index == digits) throw Error("invalid number");
                }
                if (Index < _text.Length && (_text[Index] == 'e' || _text[Index] == 'E'))
                {
                    integral = false;
                    Index++;
                    if (Index < _text.Length && (_text[Index] == '+' || _text[Index] == '-')) Index++;
                    int digits = Index;
                    while (Index < _text.Length && IsDigit(_text[Index])) Index++;
                    if (Index == digits) throw Error("invalid number");
                }
                string literal = _text.Substring(start, Index - start);
                if (integral && long.TryParse(literal, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long whole))
                {
                    return whole;
                }
                return double.Parse(literal, NumberStyles.Float, CultureInfo.InvariantCulture);
            }
        }

        internal static int Hex4(string text, int at)
        {
            if (at < 0 || at + 4 > text.Length) return -1;
            int value = 0;
            for (int i = at; i < at + 4; i++)
            {
                char c = text[i];
                int digit = c >= '0' && c <= '9' ? c - '0'
                    : c >= 'a' && c <= 'f' ? c - 'a' + 10
                    : c >= 'A' && c <= 'F' ? c - 'A' + 10
                    : -1;
                if (digit < 0) return -1;
                value = value * 16 + digit;
            }
            return value;
        }

        private static bool IsDigit(char c) => c >= '0' && c <= '9';

        /// <summary>
        /// Write a value as compact JSON. Dictionaries, sequences, strings, numbers, booleans
        /// and null are supported; anything else is written as its string form.
        /// </summary>
        public static string Stringify(object? value)
        {
            var output = new StringBuilder();
            Write(output, value, 0);
            return output.ToString();
        }

        private static void Write(StringBuilder output, object? value, int depth)
        {
            if (depth > MaxDepth) throw new ArgumentException("value nests deeper than " + MaxDepth + " levels");
            switch (value)
            {
                case null:
                    output.Append("null");
                    return;
                case string text:
                    Quote(output, text);
                    return;
                case bool flag:
                    output.Append(flag ? "true" : "false");
                    return;
                case double d:
                    output.Append(FormatDouble(d));
                    return;
                case float f:
                    output.Append(FormatDouble(f));
                    return;
                case decimal m:
                    output.Append(m.ToString(CultureInfo.InvariantCulture));
                    return;
                case IFormattable number when IsInteger(value):
                    output.Append(number.ToString(null, CultureInfo.InvariantCulture));
                    return;
                case IDictionary map:
                {
                    output.Append('{');
                    bool first = true;
                    foreach (DictionaryEntry entry in map)
                    {
                        if (!first) output.Append(',');
                        first = false;
                        Quote(output, Convert.ToString(entry.Key, CultureInfo.InvariantCulture) ?? "");
                        output.Append(':');
                        Write(output, entry.Value, depth + 1);
                    }
                    output.Append('}');
                    return;
                }
                case IEnumerable items:
                {
                    output.Append('[');
                    bool first = true;
                    foreach (object? item in items)
                    {
                        if (!first) output.Append(',');
                        first = false;
                        Write(output, item, depth + 1);
                    }
                    output.Append(']');
                    return;
                }
                default:
                    Quote(output, Convert.ToString(value, CultureInfo.InvariantCulture) ?? "");
                    return;
            }
        }

        private static bool IsInteger(object value) =>
            value is int || value is long || value is short || value is byte || value is sbyte
            || value is uint || value is ulong || value is ushort;

        /// <summary>A double as JavaScript's <c>JSON.stringify</c> writes it.</summary>
        internal static string FormatDouble(double d)
        {
            if (double.IsNaN(d) || double.IsInfinity(d)) return "null";
            if (d == Math.Floor(d) && Math.Abs(d) < 1e21)
            {
                if (d == 0) return "0";
                return d.ToString("F0", CultureInfo.InvariantCulture);
            }
            string text = d.ToString("R", CultureInfo.InvariantCulture);
            int e = text.IndexOf('E');
            if (e < 0) return text;
            string mantissa = text.Substring(0, e);
            string exponent = text.Substring(e + 1);
            char sign = exponent[0] == '-' ? '-' : '+';
            string digits = exponent.TrimStart('+', '-').TrimStart('0');
            return mantissa + "e" + sign + (digits.Length == 0 ? "0" : digits);
        }

        internal static void Quote(StringBuilder output, string value)
        {
            output.Append('"');
            output.Append(Escape(value));
            output.Append('"');
        }

        /// <summary>
        /// The content of a JSON string literal for <paramref name="value"/>, without the
        /// quotes (SPEC §11): the quote, the backslash, control characters and lone
        /// surrogates are escaped, nothing else.
        /// </summary>
        public static string Escape(string value)
        {
            StringBuilder? output = null;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                string? replacement = c switch
                {
                    '"' => "\\\"",
                    '\\' => "\\\\",
                    '\b' => "\\b",
                    '\t' => "\\t",
                    '\n' => "\\n",
                    '\f' => "\\f",
                    '\r' => "\\r",
                    _ => c < 0x20 || IsLoneSurrogate(value, i)
                        ? "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture)
                        : null,
                };
                if (replacement != null)
                {
                    output ??= new StringBuilder(value.Length + 8).Append(value, 0, i);
                    output.Append(replacement);
                }
                else
                {
                    output?.Append(c);
                }
            }
            return output == null ? value : output.ToString();
        }

        private static bool IsLoneSurrogate(string value, int i)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c)) return i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]);
            if (char.IsLowSurrogate(c)) return i == 0 || !char.IsHighSurrogate(value[i - 1]);
            return false;
        }

        /// <summary>An iterative validator: a state machine with an explicit container stack.</summary>
        private sealed class Validator
        {
            private readonly string _text;
            private int _index;

            private Validator(string text) => _text = text;

            internal static bool Valid(string text)
            {
                try
                {
                    return new Validator(text).Run();
                }
                catch (IndexOutOfRangeException)
                {
                    return false;
                }
            }

            private void Skip()
            {
                while (_index < _text.Length)
                {
                    char c = _text[_index];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') _index++;
                    else break;
                }
            }

            private bool Run()
            {
                var stack = new StringBuilder();
                Skip();
                if (!Value(stack)) return false;
                while (true)
                {
                    Skip();
                    if (stack.Length == 0) return _index == _text.Length;
                    char container = stack[stack.Length - 1];
                    if (_index >= _text.Length) return false;
                    char c = _text[_index++];
                    if (c == (container == '{' ? '}' : ']'))
                    {
                        stack.Length--;
                        continue;
                    }
                    if (c != ',') return false;
                    Skip();
                    if (container == '{' && !MemberName()) return false;
                    if (!Value(stack)) return false;
                }
            }

            private bool MemberName()
            {
                if (_index >= _text.Length || _text[_index] != '"' || !String()) return false;
                Skip();
                if (_index >= _text.Length || _text[_index] != ':') return false;
                _index++;
                Skip();
                return true;
            }

            private bool Value(StringBuilder stack)
            {
                while (true)
                {
                    if (_index >= _text.Length) return false;
                    char c = _text[_index];
                    if (c == '{' || c == '[')
                    {
                        _index++;
                        Skip();
                        char close = c == '{' ? '}' : ']';
                        if (_index < _text.Length && _text[_index] == close)
                        {
                            _index++;
                            return true;
                        }
                        stack.Append(c);
                        if (c == '{' && !MemberName()) return false;
                        continue;
                    }
                    if (c == '"') return String();
                    if (c == 't') return Word("true");
                    if (c == 'f') return Word("false");
                    if (c == 'n') return Word("null");
                    return Number();
                }
            }

            private bool Word(string word)
            {
                if (string.CompareOrdinal(_text, _index, word, 0, word.Length) != 0) return false;
                _index += word.Length;
                return true;
            }

            private bool String()
            {
                _index++;
                while (_index < _text.Length)
                {
                    char c = _text[_index++];
                    if (c == '"') return true;
                    if (c < 0x20) return false;
                    if (c == '\\')
                    {
                        if (_index >= _text.Length) return false;
                        char escape = _text[_index++];
                        if (escape == 'u')
                        {
                            if (Hex4(_text, _index) < 0) return false;
                            _index += 4;
                        }
                        else if ("\"\\/bfnrt".IndexOf(escape) < 0)
                        {
                            return false;
                        }
                    }
                }
                return false;
            }

            private bool Number()
            {
                int start = _index;
                if (_index < _text.Length && _text[_index] == '-') _index++;
                if (_index >= _text.Length) return false;
                if (_text[_index] == '0') _index++;
                else if (_text[_index] >= '1' && _text[_index] <= '9')
                {
                    while (_index < _text.Length && IsDigit(_text[_index])) _index++;
                }
                else return false;
                if (_index < _text.Length && _text[_index] == '.')
                {
                    _index++;
                    int digits = _index;
                    while (_index < _text.Length && IsDigit(_text[_index])) _index++;
                    if (_index == digits) return false;
                }
                if (_index < _text.Length && (_text[_index] == 'e' || _text[_index] == 'E'))
                {
                    _index++;
                    if (_index < _text.Length && (_text[_index] == '+' || _text[_index] == '-')) _index++;
                    int digits = _index;
                    while (_index < _text.Length && IsDigit(_text[_index])) _index++;
                    if (_index == digits) return false;
                }
                return _index > start;
            }
        }
    }
}
