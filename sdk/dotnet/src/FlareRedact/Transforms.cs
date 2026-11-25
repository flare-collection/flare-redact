using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FlareRedact
{
    /// <summary>
    /// Keyed transforms (SPEC §8): HMAC-SHA256 fingerprints, the counter-mode byte stream every
    /// engine derives identically, and the shape-preserving pseudonym and type-consistent
    /// surrogate built on it. None of them is reversible; use a <see cref="Vault"/> for that.
    /// </summary>
    public static class Transforms
    {
        private const string Lower = "abcdefghijklmnopqrstuvwxyz";
        private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string Digits = "0123456789";
        private static readonly string[] GivenNames = { "Alex", "Avery", "Casey", "Emery", "Jordan", "Morgan", "Riley", "Robin" };
        private static readonly string[] FamilyNames = { "Arden", "Blake", "Hayes", "Lane", "Parker", "Reed", "Shaw", "Vale" };
        private static readonly string[] Streets = { "Cedar", "Harbor", "Juniper", "Maple", "Orchard", "River", "Willow", "Summit" };

        /// <summary>
        /// UTF-8, with a lone surrogate encoded as U+FFFD, which is what JavaScript's
        /// <c>TextEncoder</c> does. Written out so the result does not depend on the encoder's
        /// replacement behaviour on any runtime.
        /// </summary>
        internal static byte[] Utf8(string text)
        {
            var output = new List<byte>(text.Length + 8);
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                int code = c;
                if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                {
                    code = char.ConvertToUtf32(c, text[++i]);
                }
                else if (char.IsSurrogate(c))
                {
                    code = 0xFFFD;
                }
                if (code < 0x80)
                {
                    output.Add((byte)code);
                }
                else if (code < 0x800)
                {
                    output.Add((byte)(0xC0 | (code >> 6)));
                    output.Add((byte)(0x80 | (code & 0x3F)));
                }
                else if (code < 0x10000)
                {
                    output.Add((byte)(0xE0 | (code >> 12)));
                    output.Add((byte)(0x80 | ((code >> 6) & 0x3F)));
                    output.Add((byte)(0x80 | (code & 0x3F)));
                }
                else
                {
                    output.Add((byte)(0xF0 | (code >> 18)));
                    output.Add((byte)(0x80 | ((code >> 12) & 0x3F)));
                    output.Add((byte)(0x80 | ((code >> 6) & 0x3F)));
                    output.Add((byte)(0x80 | (code & 0x3F)));
                }
            }
            return output.ToArray();
        }

        internal static byte[] HmacSha256(string secret, string message)
        {
            RequireSecret(secret);
            using var hmac = new HMACSHA256(Utf8(secret));
            return hmac.ComputeHash(Utf8(message));
        }

        internal static void RequireSecret(string? secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new FlareRedactException("a non-empty transformSecret is required for keyed transforms");
            }
        }

        internal static string Hex(byte[] bytes, int count)
        {
            var output = new StringBuilder(count * 2);
            for (int i = 0; i < count; i++) output.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
            return output.ToString();
        }

        /// <summary>The lowercase hex of the first <paramref name="bytes"/> bytes of HMAC-SHA256(secret, value).</summary>
        public static string HmacFingerprint(string secret, string value, int bytes)
        {
            byte[] sum = HmacSha256(secret, value);
            return Hex(sum, Math.Min(bytes, sum.Length));
        }

        /// <summary>
        /// <paramref name="n"/> bytes bound to <paramref name="context"/>: block i is
        /// HMAC(secret, context + "\0" + i), concatenated and cut to length.
        /// </summary>
        public static byte[] DeriveBytes(string secret, string context, int n)
        {
            RequireSecret(secret);
            var output = new byte[Math.Max(0, n)];
            int offset = 0;
            for (int counter = 0; offset < output.Length; counter++)
            {
                byte[] block = HmacSha256(secret, context + "\0" + counter.ToString(CultureInfo.InvariantCulture));
                int take = Math.Min(block.Length, output.Length - offset);
                Array.Copy(block, 0, output, offset, take);
                offset += take;
            }
            return output;
        }

        private static string? AlphabetFor(char c)
        {
            if (c >= '0' && c <= '9') return Digits;
            if (c >= 'a' && c <= 'z') return Lower;
            if (c >= 'A' && c <= 'Z') return Upper;
            return null;
        }

        /// <summary>
        /// A deterministic, keyed, shape-preserving substitution: each ASCII letter or digit
        /// becomes another of its class, everything else is kept. Not encryption and not
        /// reversible: a stable pseudonym, so joins survive.
        /// </summary>
        public static string Pseudonymize(string value, string secret)
        {
            byte[] stream = DeriveBytes(secret, "pseudonym:" + value, value.Length);
            var output = new StringBuilder(value.Length);
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                string? alphabet = AlphabetFor(c);
                output.Append(alphabet == null ? c : alphabet[stream[i] % alphabet.Length]);
            }
            return output.ToString();
        }

        private static string DigitSurrogate(string value, string secret)
        {
            byte[] stream = DeriveBytes(secret, "digits:" + value, value.Length);
            var output = new StringBuilder(value.Length);
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                output.Append(c >= '0' && c <= '9' ? Digits[stream[i] % 10] : c);
            }
            return output.ToString();
        }

        private static string LuhnCheckDigit(string prefix)
        {
            int sum = 0;
            bool twice = true;
            for (int i = prefix.Length - 1; i >= 0; i--)
            {
                char c = prefix[i];
                if (c < '0' || c > '9') continue;
                int n = c - '0';
                if (twice)
                {
                    n *= 2;
                    if (n > 9) n -= 9;
                }
                sum += n;
                twice = !twice;
            }
            return ((10 - sum % 10) % 10).ToString(CultureInfo.InvariantCulture);
        }

        private static string CardSurrogate(string value, string secret)
        {
            string shaped = DigitSurrogate(value, secret);
            int last = -1;
            for (int i = 0; i < shaped.Length; i++)
            {
                if (shaped[i] >= '0' && shaped[i] <= '9') last = i;
            }
            if (last < 0) return shaped;
            string prefix = shaped.Substring(0, last);
            return prefix + LuhnCheckDigit(prefix) + shaped.Substring(last + 1);
        }

        /// <summary>
        /// A deterministic, type-consistent synthetic value for the given detector: an email stays
        /// an email, a card stays a Luhn-valid card. Unknown detectors fall back to
        /// <see cref="Pseudonymize"/>.
        /// </summary>
        public static string Surrogate(string value, string detectorId, string secret)
        {
            switch (detectorId)
            {
                case "email":
                    return "user_" + HmacFingerprint(secret, "email:" + value, 6) + "@example.invalid";
                case "credit_card":
                    return CardSurrogate(value, secret);
                case "phone":
                    return DigitSurrogate(value, secret);
                case "person_name":
                {
                    byte[] stream = DeriveBytes(secret, "person:" + value, 2);
                    return GivenNames[stream[0] % GivenNames.Length] + " " + FamilyNames[stream[1] % FamilyNames.Length];
                }
                case "street_address":
                {
                    byte[] stream = DeriveBytes(secret, "address:" + value, 3);
                    int number = 100 + (((stream[0] << 8) | stream[1]) % 9800);
                    return number.ToString(CultureInfo.InvariantCulture) + " " + Streets[stream[2] % Streets.Length] + " Street";
                }
                default:
                    return Pseudonymize(value, secret);
            }
        }
    }
}
