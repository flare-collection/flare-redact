using System;
using System.Globalization;
using System.Numerics;

namespace FlareRedact
{
    /// <summary>
    /// The text a value under a sensitive key is replaced as (SPEC §9): a number as its decimal
    /// text, a byte array as lowercase hex, a <see cref="Guid"/> in its canonical form and
    /// characters as themselves. Every engine writes the same text, so hash and vault modes agree
    /// across languages.
    /// </summary>
    internal static class SensitiveValues
    {
        private const string Hex = "0123456789abcdef";

        /// <summary>The replacement text, or null when the value is none of those types.</summary>
        internal static string? Text(object? value)
        {
            switch (value)
            {
                case double d:
                    return JsFloat(d, false);
                case float f:
                    return JsFloat(f, true);
                case decimal m:
                    return m == decimal.Truncate(m)
                        ? decimal.Truncate(m).ToString("0", CultureInfo.InvariantCulture)
                        : JsFloat((double)m, false);
                case int _:
                case long _:
                case short _:
                case sbyte _:
                case byte _:
                case uint _:
                case ulong _:
                case ushort _:
                case BigInteger _:
                    return Convert.ToString(value, CultureInfo.InvariantCulture);
                case byte[] bytes:
                {
                    var output = new char[bytes.Length * 2];
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        output[2 * i] = Hex[bytes[i] >> 4];
                        output[2 * i + 1] = Hex[bytes[i] & 0xf];
                    }
                    return new string(output);
                }
                case Guid guid:
                    return guid.ToString("D");
                case char[] chars:
                    return new string(chars);
                case char c:
                    return c.ToString();
                default:
                    return null;
            }
        }

        /// <summary>
        /// Whether a value under a sensitive key that is neither a container nor one of the types
        /// <see cref="Text"/> knows is kept there: a boolean, or a point or span of time, which
        /// cannot carry a credential.
        /// </summary>
        internal static bool Kept(object value) =>
            value is bool || value is DateTime || value is DateTimeOffset || value is TimeSpan
#if NET8_0_OR_GREATER
            || value is DateOnly || value is TimeOnly
#endif
            ;

        /// <summary>
        /// A floating point number as ECMAScript's <c>Number::toString</c> writes it: the shortest
        /// digits that round-trip, in full from 1e-6 up to 1e21 and in exponent form outside.
        /// </summary>
        internal static string JsFloat(double value, bool single)
        {
            if (double.IsNaN(value)) return "NaN";
            if (double.IsInfinity(value)) return value > 0 ? "Infinity" : "-Infinity";
            if (value == 0) return "0";
            string sign = value < 0 ? "-" : "";
            double magnitude = Math.Abs(value);
            // The fewest digits that read back as the same number. "E" rounds the exact binary
            // value, so the first precision that round-trips also gives the closest digits.
            string? text = null;
            for (int precision = 1; precision <= 17 && text == null; precision++)
            {
                string format = "E" + (precision - 1).ToString(CultureInfo.InvariantCulture);
                string candidate = single
                    ? ((float)magnitude).ToString(format, CultureInfo.InvariantCulture)
                    : magnitude.ToString(format, CultureInfo.InvariantCulture);
                bool same = single
                    ? float.Parse(candidate, NumberStyles.Float, CultureInfo.InvariantCulture) == (float)magnitude
                    : double.Parse(candidate, NumberStyles.Float, CultureInfo.InvariantCulture) == magnitude;
                if (same) text = candidate;
            }
            if (text == null)
            {
                text = single
                    ? ((float)magnitude).ToString("R", CultureInfo.InvariantCulture)
                    : magnitude.ToString("R", CultureInfo.InvariantCulture);
            }

            string mantissa = text;
            int exponent = 0;
            int e = text.IndexOfAny(new[] { 'E', 'e' });
            if (e >= 0)
            {
                mantissa = text.Substring(0, e);
                exponent = int.Parse(text.Substring(e + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            }
            int dot = mantissa.IndexOf('.');
            string whole = dot < 0 ? mantissa : mantissa.Substring(0, dot);
            string digits = dot < 0 ? whole : whole + mantissa.Substring(dot + 1);
            int n = whole.Length + exponent;
            int lead = 0;
            while (lead < digits.Length - 1 && digits[lead] == '0') lead++;
            digits = digits.Substring(lead).TrimEnd('0');
            n -= lead;
            int k = digits.Length;

            if (k <= n && n <= 21) return sign + digits + new string('0', n - k);
            if (0 < n && n <= 21) return sign + digits.Substring(0, n) + "." + digits.Substring(n);
            if (-6 < n && n <= 0) return sign + "0." + new string('0', -n) + digits;
            string rest = k > 1 ? "." + digits.Substring(1) : "";
            int power = n - 1;
            return sign + digits[0] + rest + "e" + (power >= 0 ? "+" : "-")
                + Math.Abs(power).ToString(CultureInfo.InvariantCulture);
        }
    }
}
