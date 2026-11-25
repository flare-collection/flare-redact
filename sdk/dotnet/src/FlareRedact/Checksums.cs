using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>
    /// The named validators an FRS-1 pack may reference (SPEC §3.3). A checksum is the
    /// difference between "eleven digits" and "a Turkish national identity number": validating
    /// every national identifier is what keeps the opt-in country detectors usable on real logs.
    /// </summary>
    public static class Checksums
    {
        private const string AsciiSpace = " \t\n\r\f\u000B";

        internal static string DigitsOf(string value)
        {
            var output = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                if (c >= '0' && c <= '9') output.Append(c);
            }
            return output.ToString();
        }

        private static bool AllSameDigits(string digits)
        {
            if (digits.Length == 0) return false;
            for (int i = 1; i < digits.Length; i++)
            {
                if (digits[i] != digits[0]) return false;
            }
            return true;
        }

        private static int At(string digits, int i) => digits[i] - '0';

        private static int TwoDigits(string digits, int i) => At(digits, i) * 10 + At(digits, i + 1);

        private static bool PlausibleDate(int day, int month) => day >= 1 && day <= 31 && month >= 1 && month <= 12;

        private static string Strip(string value, string characters)
        {
            var output = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                if (characters.IndexOf(c) < 0) output.Append(c);
            }
            return output.ToString();
        }

        private static Regex Whole(string pattern) => new Regex("^(?:" + pattern + ")\\z", RegexOptions.CultureInvariant);

        private static int Int(string digits) => int.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture);

        private static long Long(string digits) => long.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture);

        /// <summary>The Luhn mod-10 checksum over the ASCII digits of a value, with a length window.</summary>
        /// <param name="value">Text whose ASCII digits are checked.</param>
        /// <param name="minDigits">The fewest digits accepted.</param>
        /// <param name="maxDigits">The most digits accepted, or 0 for no limit.</param>
        public static bool Luhn(string value, int minDigits, int maxDigits)
        {
            string d = DigitsOf(value);
            if (d.Length < minDigits || (maxDigits > 0 && d.Length > maxDigits)) return false;
            int sum = 0;
            bool twice = false;
            for (int i = d.Length - 1; i >= 0; i--)
            {
                int n = At(d, i);
                if (twice)
                {
                    n *= 2;
                    if (n > 9) n -= 9;
                }
                sum += n;
                twice = !twice;
            }
            return sum % 10 == 0;
        }

        private static readonly double Ln2 = Math.Log(2);

        /// <summary>log2, exact for powers of two as every engine's is.</summary>
        internal static double Log2(double x)
        {
            long bits = BitConverter.DoubleToInt64Bits(x);
            int exponent = (int)((bits >> 52) & 0x7FF);
            if (x > 0 && exponent != 0 && exponent != 0x7FF && (bits & 0xFFFFFFFFFFFFFL) == 0)
            {
                return exponent - 1023;
            }
            return Math.Log(x) / Ln2;
        }

        /// <summary>Shannon entropy in bits per symbol, over Unicode code points; 0 for an empty string.</summary>
        public static double ShannonEntropy(string value)
        {
            // Insertion order, so the sum adds up in the same order as JavaScript's Map.
            var frequency = new Dictionary<int, int>();
            var order = new List<int>();
            int total = 0;
            for (int i = 0; i < value.Length;)
            {
                int code = PatternTranslator.CodePointAt(value, i);
                if (frequency.TryGetValue(code, out int count))
                {
                    frequency[code] = count + 1;
                }
                else
                {
                    frequency[code] = 1;
                    order.Add(code);
                }
                total++;
                i += code > 0xFFFF ? 2 : 1;
            }
            if (total == 0) return 0;
            double entropy = 0;
            foreach (int code in order)
            {
                double p = (double)frequency[code] / total;
                entropy -= p * Log2(p);
            }
            return entropy;
        }

        private static readonly Regex PhoneYearTail = new Regex("(?:19|20)[0-9]{2}\\z", RegexOptions.CultureInvariant);
        private static readonly Regex PhoneDatedTail = new Regex("[. \\t\\n\\x0B\\f\\r-](?:19|20)[0-9]{2}\\z", RegexOptions.CultureInvariant);

        internal static bool Phone(string value)
        {
            string d = DigitsOf(value);
            if (d.Length < 8 || d.Length > 15) return false;
            if (!value.StartsWith("+", StringComparison.Ordinal))
            {
                if (d.Length < 9) return false;
                if (PhoneYearTail.IsMatch(d) && PhoneDatedTail.IsMatch(value)) return false;
            }
            return true;
        }

        private static readonly Regex IbanShape = Whole("[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}");

        internal static bool Iban(string value)
        {
            string text = Strip(value, AsciiSpace + "-   ").ToUpperInvariant();
            if (!IbanShape.IsMatch(text)) return false;
            string rearranged = text.Substring(4) + text.Substring(0, 4);
            int remainder = 0;
            foreach (char c in rearranged)
            {
                string chunk = c >= 'A' && c <= 'Z' ? (c - 55).ToString(CultureInfo.InvariantCulture) : c.ToString();
                foreach (char digit in chunk) remainder = (remainder * 10 + (digit - '0')) % 97;
            }
            return remainder == 1;
        }

        internal static bool Tckn(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11 || d[0] == '0') return false;
            int odd = At(d, 0) + At(d, 2) + At(d, 4) + At(d, 6) + At(d, 8);
            int even = At(d, 1) + At(d, 3) + At(d, 5) + At(d, 7);
            if (((odd * 7 - even) % 10 + 10) % 10 != At(d, 9)) return false;
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += At(d, i);
            return sum % 10 == At(d, 10);
        }

        internal static bool Cpf(string value)
        {
            string c = DigitsOf(value);
            if (c.Length != 11 || AllSameDigits(c)) return false;
            for (int length = 9; length <= 10; length++)
            {
                int sum = 0;
                for (int i = 0; i < length; i++) sum += At(c, i) * (length + 1 - i);
                int r = sum * 10 % 11;
                if (r == 10) r = 0;
                if (r != At(c, length)) return false;
            }
            return true;
        }

        private const string DniLetters = "TRWAGMYFPDXBNJZSQVHLCKE";
        private static readonly Regex DniShape = Whole("([XYZ]?)([0-9]{7,8})([A-Z])");

        internal static bool Dni(string value)
        {
            Match m = DniShape.Match(Strip(value, AsciiSpace + "-").ToUpperInvariant());
            if (!m.Success) return false;
            string prefix = m.Groups[1].Value.Length == 0 ? "" : "XYZ".IndexOf(m.Groups[1].Value[0]).ToString(CultureInfo.InvariantCulture);
            long n = Long(prefix + m.Groups[2].Value);
            return DniLetters[(int)(n % 23)] == m.Groups[3].Value[0];
        }

        internal static bool Bsn(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 9 || d == "000000000") return false;
            int sum = 0;
            for (int i = 0; i < 8; i++) sum += At(d, i) * (9 - i);
            sum -= At(d, 8);
            return sum % 11 == 0;
        }

        internal static bool Pesel(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11) return false;
            int[] weights = { 1, 3, 7, 9, 1, 3, 7, 9, 1, 3 };
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += At(d, i) * weights[i];
            return (10 - sum % 10) % 10 == At(d, 10);
        }

        internal static bool DeTaxId(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11) return false;
            int product = 10;
            for (int i = 0; i < 10; i++)
            {
                int sum = (At(d, i) + product) % 10;
                if (sum == 0) sum = 10;
                product = sum * 2 % 11;
            }
            return (11 - product) % 10 == At(d, 10);
        }

        private const string CfOddKeys = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static readonly int[] CfOddValues =
        {
            1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
            1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
        };
        private static readonly Regex CfShape = Whole("[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]");

        internal static bool CodiceFiscale(string value)
        {
            string cf = value.ToUpperInvariant();
            if (!CfShape.IsMatch(cf)) return false;
            int sum = 0;
            for (int i = 0; i < 15; i++)
            {
                char c = cf[i];
                if (i % 2 == 0) sum += CfOddValues[CfOddKeys.IndexOf(c)];
                else if (c >= '0' && c <= '9') sum += c - '0';
                else sum += c - 'A';
            }
            return (char)('A' + sum % 26) == cf[15];
        }

        private static readonly Regex NirShape = Whole("([12][0-9]{4})([0-9]{2}|2[AB])([0-9]{6})([0-9]{2})");

        internal static bool FrNir(string value)
        {
            Match m = NirShape.Match(Strip(value, AsciiSpace + ".-").ToUpperInvariant());
            if (!m.Success) return false;
            string department = m.Groups[2].Value;
            if (department == "2A") department = "19";
            else if (department == "2B") department = "18";
            long n = Long(m.Groups[1].Value + department + m.Groups[3].Value);
            return 97 - n % 97 == Int(m.Groups[4].Value);
        }

        private static readonly int[][] VerhoeffD =
        {
            new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new[] { 1, 2, 3, 4, 0, 6, 7, 8, 9, 5 },
            new[] { 2, 3, 4, 0, 1, 7, 8, 9, 5, 6 }, new[] { 3, 4, 0, 1, 2, 8, 9, 5, 6, 7 },
            new[] { 4, 0, 1, 2, 3, 9, 5, 6, 7, 8 }, new[] { 5, 9, 8, 7, 6, 0, 4, 3, 2, 1 },
            new[] { 6, 5, 9, 8, 7, 1, 0, 4, 3, 2 }, new[] { 7, 6, 5, 9, 8, 2, 1, 0, 4, 3 },
            new[] { 8, 7, 6, 5, 9, 3, 2, 1, 0, 4 }, new[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
        };
        private static readonly int[][] VerhoeffP =
        {
            new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new[] { 1, 5, 7, 6, 2, 8, 3, 0, 9, 4 },
            new[] { 5, 8, 0, 3, 7, 9, 6, 1, 4, 2 }, new[] { 8, 9, 1, 6, 0, 4, 3, 5, 2, 7 },
            new[] { 9, 4, 5, 3, 1, 2, 6, 8, 7, 0 }, new[] { 4, 2, 8, 6, 5, 7, 3, 9, 0, 1 },
            new[] { 2, 7, 9, 3, 8, 0, 6, 4, 1, 5 }, new[] { 7, 0, 4, 6, 9, 1, 3, 2, 5, 8 },
        };

        internal static bool Aadhaar(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 12 || d[0] == '0' || d[0] == '1') return false;
            int c = 0;
            for (int i = 0; i < 12; i++) c = VerhoeffD[c][VerhoeffP[i % 8][At(d, 11 - i)]];
            return c == 0;
        }

        internal static bool Tfn(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 9 || AllSameDigits(d)) return false;
            int[] weights = { 1, 4, 3, 7, 5, 8, 6, 9, 10 };
            int sum = 0;
            for (int i = 0; i < 9; i++) sum += At(d, i) * weights[i];
            return sum % 11 == 0;
        }

        private static readonly int[] CnWeights = { 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2 };
        private const string CnCheck = "10X98765432";
        private static readonly Regex CnShape = Whole(
            "[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9X]");

        internal static bool CnResidentId(string value)
        {
            string id = value.ToUpperInvariant();
            if (!CnShape.IsMatch(id)) return false;
            int sum = 0;
            for (int i = 0; i < 17; i++) sum += At(id, i) * CnWeights[i];
            return CnCheck[sum % 11] == id[17];
        }

        internal static bool JpMyNumber(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 12) return false;
            int sum = 0;
            for (int n = 1; n <= 11; n++)
            {
                int weight = n > 6 ? n - 5 : n + 1;
                sum += At(d, 11 - n) * weight;
            }
            int r = sum % 11;
            int check = r > 1 ? 11 - r : 0;
            return check == At(d, 11);
        }

        private static readonly Regex SsnShape = Whole("([0-9]{3})[- ]?([0-9]{2})[- ]?([0-9]{4})");

        internal static bool UsSsn(string value)
        {
            Match m = SsnShape.Match(value);
            if (!m.Success) return false;
            int area = Int(m.Groups[1].Value);
            int group = Int(m.Groups[2].Value);
            int serial = Int(m.Groups[3].Value);
            if (area == 0 || area == 666 || area >= 900) return false;
            return group != 0 && serial != 0;
        }

        internal static bool Aba(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 9) return false;
            int sum = 0;
            for (int i = 0; i < 9; i += 3) sum += 3 * At(d, i) + 7 * At(d, i + 1) + At(d, i + 2);
            return sum != 0 && sum % 10 == 0;
        }

        internal static bool Nhs(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 10 || AllSameDigits(d)) return false;
            int sum = 0;
            for (int i = 0; i < 9; i++) sum += At(d, i) * (10 - i);
            int check = 11 - sum % 11;
            if (check == 11) check = 0;
            return check != 10 && check == At(d, 9);
        }

        private const string VinKeys = "ABCDEFGHJKLMNPRSTUVWXYZ";
        private static readonly int[] VinValues = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9, 2, 3, 4, 5, 6, 7, 8, 9 };
        private static readonly int[] VinWeights = { 8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2 };
        private static readonly Regex VinShape = Whole("[A-HJ-NPR-Z0-9]{17}");

        internal static bool Vin(string value)
        {
            string v = value.ToUpperInvariant();
            if (!VinShape.IsMatch(v)) return false;
            int sum = 0;
            for (int i = 0; i < 17; i++)
            {
                char c = v[i];
                int t;
                if (c >= '0' && c <= '9')
                {
                    t = c - '0';
                }
                else
                {
                    int index = VinKeys.IndexOf(c);
                    if (index < 0) return false;
                    t = VinValues[index];
                }
                sum += t * VinWeights[i];
            }
            int check = sum % 11;
            char expected = check == 10 ? 'X' : (char)('0' + check);
            return v[8] == expected;
        }

        private static readonly int[] CnpWeights = { 2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9 };

        internal static bool Cnp(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 13 || d[0] == '0' || !PlausibleDate(TwoDigits(d, 5), TwoDigits(d, 3))) return false;
            int sum = 0;
            for (int i = 0; i < 12; i++) sum += At(d, i) * CnpWeights[i];
            int r = sum % 11;
            if (r == 10) r = 1;
            return r == At(d, 12);
        }

        private static readonly Regex AllDigits = Whole("[0-9]+");

        internal static bool Personnummer(string value)
        {
            string d = Strip(value, "-+");
            if (!AllDigits.IsMatch(d)) return false;
            if (d.Length == 12)
            {
                string century = d.Substring(0, 2);
                if (century != "18" && century != "19" && century != "20") return false;
                d = d.Substring(2);
            }
            if (d.Length != 10) return false;
            int day = TwoDigits(d, 4);
            if (day > 60) day -= 60;
            return PlausibleDate(day, TwoDigits(d, 2)) && Luhn(d, 2, 0);
        }

        private static readonly Regex HetuShape = Whole("([0-9]{2})([0-9]{2})([0-9]{2})[-+A-FU-Y]([0-9]{3})([0-9A-FHJ-NPR-Y])");
        private const string HetuCheck = "0123456789ABCDEFHJKLMNPRSTUVWXY";

        internal static bool Hetu(string value)
        {
            Match m = HetuShape.Match(value);
            if (!m.Success) return false;
            int day = Int(m.Groups[1].Value);
            int month = Int(m.Groups[2].Value);
            int individual = Int(m.Groups[4].Value);
            if (!PlausibleDate(day, month) || individual < 2) return false;
            long n = Long(m.Groups[1].Value + m.Groups[2].Value + m.Groups[3].Value + m.Groups[4].Value);
            return HetuCheck[(int)(n % 31)] == m.Groups[5].Value[0];
        }

        private static readonly int[] FnrW1 = { 3, 7, 6, 1, 8, 9, 4, 5, 2 };
        private static readonly int[] FnrW2 = { 5, 4, 3, 2, 7, 6, 5, 4, 3, 2 };

        internal static bool Fodselsnummer(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11) return false;
            int day = TwoDigits(d, 0);
            int month = TwoDigits(d, 2);
            if (day > 40) day -= 40;
            if (month > 40) month -= 40;
            if (!PlausibleDate(day, month)) return false;
            return Mod11Check(d, FnrW1) == At(d, 9) && Mod11Check(d, FnrW2) == At(d, 10);
        }

        private static int Mod11Check(string d, int[] weights)
        {
            int sum = 0;
            for (int i = 0; i < weights.Length; i++) sum += At(d, i) * weights[i];
            return (11 - sum % 11) % 11;
        }

        internal static bool BeNationalNumber(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11) return false;
            int month = TwoDigits(d, 2);
            if (month > 52 || month % 20 > 12) return false;
            long body = Long(d.Substring(0, 9));
            long check = Long(d.Substring(9));
            return 97 - body % 97 == check || 97 - (2_000_000_000L + body) % 97 == check;
        }

        internal static bool PtNif(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 9) return false;
            char first = d[0];
            if (!(first == '1' || first == '2' || first == '3' || d.StartsWith("45", StringComparison.Ordinal))) return false;
            int sum = 0;
            for (int i = 0; i < 8; i++) sum += At(d, i) * (9 - i);
            return (11 - sum % 11) % 11 % 10 == At(d, 8);
        }

        internal static bool ZaId(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 13 || d[10] > '2' || !PlausibleDate(TwoDigits(d, 4), TwoDigits(d, 2))) return false;
            return Luhn(d, 2, 0);
        }

        private static readonly Regex CurpShape = Whole(
            "[A-Z]{4}([0-9]{2})([0-9]{2})([0-9]{2})[HM]([A-Z]{2})[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z][0-9]");
        private static readonly HashSet<string> CurpStates = new HashSet<string>(StringComparer.Ordinal)
        {
            "AS", "BC", "BS", "CC", "CH", "CL", "CM", "CS", "DF", "DG", "GR", "GT", "HG", "JC", "MC", "MN",
            "MS", "NE", "NL", "NT", "OC", "PL", "QR", "QT", "SL", "SP", "SR", "TC", "TL", "TS", "VZ", "YN", "ZS",
        };

        internal static bool Curp(string value)
        {
            Match m = CurpShape.Match(value);
            if (!m.Success) return false;
            int day = Int(m.Groups[3].Value);
            int month = Int(m.Groups[2].Value);
            if (!PlausibleDate(day, month) || !CurpStates.Contains(m.Groups[4].Value)) return false;
            int sum = 0;
            for (int i = 0; i < 17; i++)
            {
                int c = value[i];
                int v = c <= '9' ? c - '0' : c <= 'N' ? c - 55 : c - 54;
                sum += v * (18 - i);
            }
            return (10 - sum % 10) % 10 == value[17] - '0';
        }

        private static readonly Regex RutShape = Whole("([0-9]{7,8})([0-9K])");

        internal static bool Rut(string value)
        {
            Match m = RutShape.Match(Strip(value, AsciiSpace + ".-").ToUpperInvariant());
            if (!m.Success) return false;
            string body = m.Groups[1].Value;
            int sum = 0;
            int weight = 2;
            for (int i = body.Length - 1; i >= 0; i--)
            {
                sum += At(body, i) * weight;
                weight = weight == 7 ? 2 : weight + 1;
            }
            int check = 11 - sum % 11;
            string expected = check == 11 ? "0" : check == 10 ? "K" : check.ToString(CultureInfo.InvariantCulture);
            return expected == m.Groups[2].Value;
        }

        private static readonly int[] CuitWeights = { 5, 4, 3, 2, 7, 6, 5, 4, 3, 2 };

        internal static bool Cuit(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11) return false;
            string prefix = d.Substring(0, 2);
            if (prefix != "20" && prefix != "23" && prefix != "24" && prefix != "27") return false;
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += At(d, i) * CuitWeights[i];
            int remainder = sum % 11;
            int check = remainder == 0 ? 0 : remainder == 1 ? 9 : 11 - remainder;
            return check == At(d, 10);
        }

        private static readonly Regex NricShape = Whole("([STFG])([0-9]{7})([A-Z])");
        private static readonly int[] NricWeights = { 2, 7, 6, 5, 4, 3, 2 };

        internal static bool Nric(string value)
        {
            Match m = NricShape.Match(value);
            if (!m.Success) return false;
            string series = m.Groups[1].Value;
            int sum = series == "T" || series == "G" ? 4 : 0;
            for (int i = 0; i < 7; i++) sum += At(m.Groups[2].Value, i) * NricWeights[i];
            string letters = series == "S" || series == "T" ? "JZIHGFEDCBA" : "XWUTRQPNMLK";
            return letters[sum % 11] == m.Groups[3].Value[0];
        }

        internal static bool Amka(string value)
        {
            string d = DigitsOf(value);
            if (d.Length != 11 || !PlausibleDate(TwoDigits(d, 0), TwoDigits(d, 2))) return false;
            return Luhn(d, 2, 0);
        }

        private static readonly Regex NinoShape = Whole("[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][0-9]{6}[A-D]");
        private static readonly HashSet<string> NinoUnused = new HashSet<string>(StringComparer.Ordinal)
        {
            "BG", "GB", "KN", "NK", "NT", "TN", "ZZ",
        };

        internal static bool UkNino(string value)
        {
            string n = value.Replace(" ", "");
            return NinoShape.IsMatch(n) && !NinoUnused.Contains(n.Substring(0, 2));
        }

        /// <summary>The vocabulary a pack may reference by name. An unknown name is a load error.</summary>
        internal static readonly IReadOnlyDictionary<string, Func<string, bool>> Named =
            new Dictionary<string, Func<string, bool>>(StringComparer.Ordinal)
            {
                ["phone"] = Phone,
                ["iban"] = Iban,
                ["tckn"] = Tckn,
                ["cpf"] = Cpf,
                ["dni"] = Dni,
                ["bsn"] = Bsn,
                ["pesel"] = Pesel,
                ["de_tax_id"] = DeTaxId,
                ["codice_fiscale"] = CodiceFiscale,
                ["fr_nir"] = FrNir,
                ["aadhaar"] = Aadhaar,
                ["tfn"] = Tfn,
                ["cn_resident_id"] = CnResidentId,
                ["jp_my_number"] = JpMyNumber,
                ["us_ssn"] = UsSsn,
                ["aba"] = Aba,
                ["nhs"] = Nhs,
                ["vin"] = Vin,
                ["cnp"] = Cnp,
                ["personnummer"] = Personnummer,
                ["hetu"] = Hetu,
                ["fodselsnummer"] = Fodselsnummer,
                ["be_national_number"] = BeNationalNumber,
                ["pt_nif"] = PtNif,
                ["za_id"] = ZaId,
                ["curp"] = Curp,
                ["rut"] = Rut,
                ["cuit"] = Cuit,
                ["nric"] = Nric,
                ["amka"] = Amka,
                ["uk_nino"] = UkNino,
            };
    }
}
