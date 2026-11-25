package io.github.flarecollection.redact;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The named validators an FRS-1 pack may reference (SPEC §3.3). A checksum is the
 * difference between "eleven digits" and "a Turkish national identity number":
 * validating every national identifier is what keeps the opt-in country detectors
 * usable on real logs.
 */
public final class Checksums {
    private Checksums() {
    }

    static String digitsOf(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= '0' && c <= '9') {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static boolean allSameDigits(String digits) {
        if (digits.isEmpty()) {
            return false;
        }
        for (int i = 1; i < digits.length(); i++) {
            if (digits.charAt(i) != digits.charAt(0)) {
                return false;
            }
        }
        return true;
    }

    private static int at(String digits, int i) {
        return digits.charAt(i) - '0';
    }

    private static int twoDigits(String digits, int i) {
        return at(digits, i) * 10 + at(digits, i + 1);
    }

    private static boolean plausibleDate(int day, int month) {
        return day >= 1 && day <= 31 && month >= 1 && month <= 12;
    }

    private static String strip(String value, String characters) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (characters.indexOf(c) < 0) {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static final String ASCII_SPACE = " \t\n\r\f\u000B";

    /**
     * The Luhn mod-10 checksum over the digits of {@code value}, with a length window.
     *
     * @param value text whose ASCII digits are checked
     * @param minDigits the fewest digits accepted
     * @param maxDigits the most digits accepted, or 0 for no limit
     * @return true when the digits pass
     */
    public static boolean luhn(String value, int minDigits, int maxDigits) {
        String d = digitsOf(value);
        if (d.length() < minDigits || (maxDigits > 0 && d.length() > maxDigits)) {
            return false;
        }
        int sum = 0;
        boolean twice = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int n = at(d, i);
            if (twice) {
                n *= 2;
                if (n > 9) {
                    n -= 9;
                }
            }
            sum += n;
            twice = !twice;
        }
        return sum % 10 == 0;
    }

    private static final double LN2 = Math.log(2);

    static double log2(double x) {
        int exponent = Math.getExponent(x);
        if (x == Math.scalb(1.0, exponent)) {
            return exponent;
        }
        return Math.log(x) / LN2;
    }

    /**
     * Shannon entropy in bits per symbol, over Unicode code points.
     *
     * @param value any string
     * @return the entropy, 0 for an empty string
     */
    public static double shannonEntropy(String value) {
        Map<Integer, Integer> frequency = new HashMap<>();
        int total = 0;
        for (int i = 0; i < value.length(); ) {
            int code = value.codePointAt(i);
            frequency.merge(code, 1, Integer::sum);
            total++;
            i += Character.charCount(code);
        }
        if (total == 0) {
            return 0;
        }
        double entropy = 0;
        for (int count : frequency.values()) {
            double p = (double) count / total;
            entropy -= p * log2(p);
        }
        return entropy;
    }

    private static final Pattern PHONE_YEAR_TAIL = Pattern.compile("(?:19|20)[0-9]{2}\\z");
    private static final Pattern PHONE_DATED_TAIL = Pattern.compile("[. \\t\\n\\x0B\\f\\r-](?:19|20)[0-9]{2}\\z");

    static boolean phone(String value) {
        String d = digitsOf(value);
        if (d.length() < 8 || d.length() > 15) {
            return false;
        }
        if (!value.startsWith("+")) {
            if (d.length() < 9) {
                return false;
            }
            if (PHONE_YEAR_TAIL.matcher(d).find() && PHONE_DATED_TAIL.matcher(value).find()) {
                return false;
            }
        }
        return true;
    }

    private static final Pattern IBAN_SHAPE = Pattern.compile("[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}");

    static boolean iban(String value) {
        String text = strip(value, ASCII_SPACE + "-" + (char) 0xA0 + (char) 0x2009 + (char) 0x202F).toUpperCase(Locale.ROOT);
        if (!IBAN_SHAPE.matcher(text).matches()) {
            return false;
        }
        String rearranged = text.substring(4) + text.substring(0, 4);
        int remainder = 0;
        for (int i = 0; i < rearranged.length(); i++) {
            char c = rearranged.charAt(i);
            String chunk = c >= 'A' && c <= 'Z' ? Integer.toString(c - 55) : String.valueOf(c);
            for (int j = 0; j < chunk.length(); j++) {
                remainder = (remainder * 10 + (chunk.charAt(j) - '0')) % 97;
            }
        }
        return remainder == 1;
    }

    static boolean tckn(String value) {
        String d = digitsOf(value);
        if (d.length() != 11 || d.charAt(0) == '0') {
            return false;
        }
        int odd = at(d, 0) + at(d, 2) + at(d, 4) + at(d, 6) + at(d, 8);
        int even = at(d, 1) + at(d, 3) + at(d, 5) + at(d, 7);
        if (((odd * 7 - even) % 10 + 10) % 10 != at(d, 9)) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += at(d, i);
        }
        return sum % 10 == at(d, 10);
    }

    static boolean cpf(String value) {
        String c = digitsOf(value);
        if (c.length() != 11 || allSameDigits(c)) {
            return false;
        }
        for (int length = 9; length <= 10; length++) {
            int sum = 0;
            for (int i = 0; i < length; i++) {
                sum += at(c, i) * (length + 1 - i);
            }
            int r = (sum * 10) % 11;
            if (r == 10) {
                r = 0;
            }
            if (r != at(c, length)) {
                return false;
            }
        }
        return true;
    }

    private static final String DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";
    private static final Pattern DNI_SHAPE = Pattern.compile("([XYZ]?)([0-9]{7,8})([A-Z])");

    static boolean dni(String value) {
        Matcher m = DNI_SHAPE.matcher(strip(value, ASCII_SPACE + "-").toUpperCase(Locale.ROOT));
        if (!m.matches()) {
            return false;
        }
        String prefix = m.group(1).isEmpty() ? "" : Integer.toString("XYZ".indexOf(m.group(1)));
        long n = Long.parseLong(prefix + m.group(2));
        return DNI_LETTERS.charAt((int) (n % 23)) == m.group(3).charAt(0);
    }

    static boolean bsn(String value) {
        String d = digitsOf(value);
        if (d.length() != 9 || d.equals("000000000")) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 8; i++) {
            sum += at(d, i) * (9 - i);
        }
        sum -= at(d, 8);
        return sum % 11 == 0;
    }

    static boolean pesel(String value) {
        String d = digitsOf(value);
        if (d.length() != 11) {
            return false;
        }
        int[] weights = {1, 3, 7, 9, 1, 3, 7, 9, 1, 3};
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += at(d, i) * weights[i];
        }
        return (10 - sum % 10) % 10 == at(d, 10);
    }

    static boolean deTaxId(String value) {
        String d = digitsOf(value);
        if (d.length() != 11) {
            return false;
        }
        int product = 10;
        for (int i = 0; i < 10; i++) {
            int sum = (at(d, i) + product) % 10;
            if (sum == 0) {
                sum = 10;
            }
            product = (sum * 2) % 11;
        }
        return (11 - product) % 10 == at(d, 10);
    }

    private static final String CF_ODD_KEYS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final int[] CF_ODD_VALUES = {
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
    };
    private static final Pattern CF_SHAPE = Pattern.compile("[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]");

    static boolean codiceFiscale(String value) {
        String cf = value.toUpperCase(Locale.ROOT);
        if (!CF_SHAPE.matcher(cf).matches()) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 15; i++) {
            char c = cf.charAt(i);
            if (i % 2 == 0) {
                sum += CF_ODD_VALUES[CF_ODD_KEYS.indexOf(c)];
            } else if (c >= '0' && c <= '9') {
                sum += c - '0';
            } else {
                sum += c - 'A';
            }
        }
        return (char) ('A' + sum % 26) == cf.charAt(15);
    }

    private static final Pattern NIR_SHAPE = Pattern.compile("([12][0-9]{4})([0-9]{2}|2[AB])([0-9]{6})([0-9]{2})");

    static boolean frNir(String value) {
        Matcher m = NIR_SHAPE.matcher(strip(value, ASCII_SPACE + ".-").toUpperCase(Locale.ROOT));
        if (!m.matches()) {
            return false;
        }
        String department = m.group(2);
        if (department.equals("2A")) {
            department = "19";
        } else if (department.equals("2B")) {
            department = "18";
        }
        long n = Long.parseLong(m.group(1) + department + m.group(3));
        return 97 - n % 97 == Integer.parseInt(m.group(4));
    }

    private static final int[][] VERHOEFF_D = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
        {2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
        {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
        {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
        {8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
    };
    private static final int[][] VERHOEFF_P = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
        {5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
        {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
        {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
    };

    static boolean aadhaar(String value) {
        String d = digitsOf(value);
        if (d.length() != 12 || d.charAt(0) == '0' || d.charAt(0) == '1') {
            return false;
        }
        int c = 0;
        for (int i = 0; i < 12; i++) {
            c = VERHOEFF_D[c][VERHOEFF_P[i % 8][at(d, 11 - i)]];
        }
        return c == 0;
    }

    static boolean tfn(String value) {
        String d = digitsOf(value);
        if (d.length() != 9 || allSameDigits(d)) {
            return false;
        }
        int[] weights = {1, 4, 3, 7, 5, 8, 6, 9, 10};
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            sum += at(d, i) * weights[i];
        }
        return sum % 11 == 0;
    }

    private static final int[] CN_WEIGHTS = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    private static final String CN_CHECK = "10X98765432";
    private static final Pattern CN_SHAPE = Pattern.compile(
        "[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9X]");

    static boolean cnResidentId(String value) {
        String id = value.toUpperCase(Locale.ROOT);
        if (!CN_SHAPE.matcher(id).matches()) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            sum += at(id, i) * CN_WEIGHTS[i];
        }
        return CN_CHECK.charAt(sum % 11) == id.charAt(17);
    }

    static boolean jpMyNumber(String value) {
        String d = digitsOf(value);
        if (d.length() != 12) {
            return false;
        }
        int sum = 0;
        for (int n = 1; n <= 11; n++) {
            int weight = n > 6 ? n - 5 : n + 1;
            sum += at(d, 11 - n) * weight;
        }
        int r = sum % 11;
        int check = r > 1 ? 11 - r : 0;
        return check == at(d, 11);
    }

    private static final Pattern SSN_SHAPE = Pattern.compile("([0-9]{3})[- ]?([0-9]{2})[- ]?([0-9]{4})");

    static boolean usSsn(String value) {
        Matcher m = SSN_SHAPE.matcher(value);
        if (!m.matches()) {
            return false;
        }
        int area = Integer.parseInt(m.group(1));
        int group = Integer.parseInt(m.group(2));
        int serial = Integer.parseInt(m.group(3));
        if (area == 0 || area == 666 || area >= 900) {
            return false;
        }
        return group != 0 && serial != 0;
    }

    static boolean aba(String value) {
        String d = digitsOf(value);
        if (d.length() != 9) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 9; i += 3) {
            sum += 3 * at(d, i) + 7 * at(d, i + 1) + at(d, i + 2);
        }
        return sum != 0 && sum % 10 == 0;
    }

    static boolean nhs(String value) {
        String d = digitsOf(value);
        if (d.length() != 10 || allSameDigits(d)) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            sum += at(d, i) * (10 - i);
        }
        int check = 11 - sum % 11;
        if (check == 11) {
            check = 0;
        }
        return check != 10 && check == at(d, 9);
    }

    private static final String VIN_KEYS = "ABCDEFGHJKLMNPRSTUVWXYZ";
    private static final int[] VIN_VALUES = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9, 2, 3, 4, 5, 6, 7, 8, 9};
    private static final int[] VIN_WEIGHTS = {8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2};
    private static final Pattern VIN_SHAPE = Pattern.compile("[A-HJ-NPR-Z0-9]{17}");

    static boolean vin(String value) {
        String v = value.toUpperCase(Locale.ROOT);
        if (!VIN_SHAPE.matcher(v).matches()) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            char c = v.charAt(i);
            int t;
            if (c >= '0' && c <= '9') {
                t = c - '0';
            } else {
                int index = VIN_KEYS.indexOf(c);
                if (index < 0) {
                    return false;
                }
                t = VIN_VALUES[index];
            }
            sum += t * VIN_WEIGHTS[i];
        }
        int check = sum % 11;
        char expected = check == 10 ? 'X' : (char) ('0' + check);
        return v.charAt(8) == expected;
    }

    private static final int[] CNP_WEIGHTS = {2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9};

    static boolean cnp(String value) {
        String d = digitsOf(value);
        if (d.length() != 13 || d.charAt(0) == '0' || !plausibleDate(twoDigits(d, 5), twoDigits(d, 3))) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 12; i++) {
            sum += at(d, i) * CNP_WEIGHTS[i];
        }
        int r = sum % 11;
        if (r == 10) {
            r = 1;
        }
        return r == at(d, 12);
    }

    private static final Pattern ALL_DIGITS = Pattern.compile("[0-9]+");

    static boolean personnummer(String value) {
        String d = strip(value, "-+");
        if (!ALL_DIGITS.matcher(d).matches()) {
            return false;
        }
        if (d.length() == 12) {
            String century = d.substring(0, 2);
            if (!century.equals("18") && !century.equals("19") && !century.equals("20")) {
                return false;
            }
            d = d.substring(2);
        }
        if (d.length() != 10) {
            return false;
        }
        int day = twoDigits(d, 4);
        if (day > 60) {
            day -= 60;
        }
        return plausibleDate(day, twoDigits(d, 2)) && luhn(d, 2, 0);
    }

    private static final Pattern HETU_SHAPE = Pattern.compile(
        "([0-9]{2})([0-9]{2})([0-9]{2})[-+A-FU-Y]([0-9]{3})([0-9A-FHJ-NPR-Y])");
    private static final String HETU_CHECK = "0123456789ABCDEFHJKLMNPRSTUVWXY";

    static boolean hetu(String value) {
        Matcher m = HETU_SHAPE.matcher(value);
        if (!m.matches()) {
            return false;
        }
        int day = Integer.parseInt(m.group(1));
        int month = Integer.parseInt(m.group(2));
        int individual = Integer.parseInt(m.group(4));
        if (!plausibleDate(day, month) || individual < 2) {
            return false;
        }
        long n = Long.parseLong(m.group(1) + m.group(2) + m.group(3) + m.group(4));
        return HETU_CHECK.charAt((int) (n % 31)) == m.group(5).charAt(0);
    }

    private static final int[] FNR_W1 = {3, 7, 6, 1, 8, 9, 4, 5, 2};
    private static final int[] FNR_W2 = {5, 4, 3, 2, 7, 6, 5, 4, 3, 2};

    static boolean fodselsnummer(String value) {
        String d = digitsOf(value);
        if (d.length() != 11) {
            return false;
        }
        int day = twoDigits(d, 0);
        int month = twoDigits(d, 2);
        if (day > 40) {
            day -= 40;
        }
        if (month > 40) {
            month -= 40;
        }
        if (!plausibleDate(day, month)) {
            return false;
        }
        return mod11Check(d, FNR_W1) == at(d, 9) && mod11Check(d, FNR_W2) == at(d, 10);
    }

    private static int mod11Check(String d, int[] weights) {
        int sum = 0;
        for (int i = 0; i < weights.length; i++) {
            sum += at(d, i) * weights[i];
        }
        return (11 - sum % 11) % 11;
    }

    static boolean beNationalNumber(String value) {
        String d = digitsOf(value);
        if (d.length() != 11) {
            return false;
        }
        int month = twoDigits(d, 2);
        if (month > 52 || month % 20 > 12) {
            return false;
        }
        long base = Long.parseLong(d.substring(0, 9));
        long check = Long.parseLong(d.substring(9));
        return 97 - base % 97 == check || 97 - (2_000_000_000L + base) % 97 == check;
    }

    static boolean ptNif(String value) {
        String d = digitsOf(value);
        if (d.length() != 9) {
            return false;
        }
        char first = d.charAt(0);
        if (!(first == '1' || first == '2' || first == '3' || d.startsWith("45"))) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 8; i++) {
            sum += at(d, i) * (9 - i);
        }
        return (11 - sum % 11) % 11 % 10 == at(d, 8);
    }

    static boolean zaId(String value) {
        String d = digitsOf(value);
        if (d.length() != 13 || d.charAt(10) > '2' || !plausibleDate(twoDigits(d, 4), twoDigits(d, 2))) {
            return false;
        }
        return luhn(d, 2, 0);
    }

    private static final Pattern CURP_SHAPE = Pattern.compile(
        "[A-Z]{4}([0-9]{2})([0-9]{2})([0-9]{2})[HM]([A-Z]{2})[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z][0-9]");
    private static final Set<String> CURP_STATES = new HashSet<>(Arrays.asList(
        "AS", "BC", "BS", "CC", "CH", "CL", "CM", "CS", "DF", "DG", "GR", "GT", "HG", "JC", "MC", "MN",
        "MS", "NE", "NL", "NT", "OC", "PL", "QR", "QT", "SL", "SP", "SR", "TC", "TL", "TS", "VZ", "YN", "ZS"));

    static boolean curp(String value) {
        Matcher m = CURP_SHAPE.matcher(value);
        if (!m.matches()) {
            return false;
        }
        int day = Integer.parseInt(m.group(3));
        int month = Integer.parseInt(m.group(2));
        if (!plausibleDate(day, month) || !CURP_STATES.contains(m.group(4))) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            int c = value.charAt(i);
            int v = c <= '9' ? c - '0' : c <= 'N' ? c - 55 : c - 54;
            sum += v * (18 - i);
        }
        return (10 - sum % 10) % 10 == value.charAt(17) - '0';
    }

    private static final Pattern RUT_SHAPE = Pattern.compile("([0-9]{7,8})([0-9K])");

    static boolean rut(String value) {
        Matcher m = RUT_SHAPE.matcher(strip(value, ASCII_SPACE + ".-").toUpperCase(Locale.ROOT));
        if (!m.matches()) {
            return false;
        }
        String body = m.group(1);
        int sum = 0;
        int weight = 2;
        for (int i = body.length() - 1; i >= 0; i--) {
            sum += at(body, i) * weight;
            weight = weight == 7 ? 2 : weight + 1;
        }
        int check = 11 - sum % 11;
        String expected = check == 11 ? "0" : check == 10 ? "K" : Integer.toString(check);
        return expected.equals(m.group(2));
    }

    private static final int[] CUIT_WEIGHTS = {5, 4, 3, 2, 7, 6, 5, 4, 3, 2};

    static boolean cuit(String value) {
        String d = digitsOf(value);
        if (d.length() != 11) {
            return false;
        }
        String prefix = d.substring(0, 2);
        if (!prefix.equals("20") && !prefix.equals("23") && !prefix.equals("24") && !prefix.equals("27")) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += at(d, i) * CUIT_WEIGHTS[i];
        }
        int remainder = sum % 11;
        int check = remainder == 0 ? 0 : remainder == 1 ? 9 : 11 - remainder;
        return check == at(d, 10);
    }

    private static final Pattern NRIC_SHAPE = Pattern.compile("([STFG])([0-9]{7})([A-Z])");
    private static final int[] NRIC_WEIGHTS = {2, 7, 6, 5, 4, 3, 2};

    static boolean nric(String value) {
        Matcher m = NRIC_SHAPE.matcher(value);
        if (!m.matches()) {
            return false;
        }
        String series = m.group(1);
        int sum = series.equals("T") || series.equals("G") ? 4 : 0;
        for (int i = 0; i < 7; i++) {
            sum += at(m.group(2), i) * NRIC_WEIGHTS[i];
        }
        String letters = series.equals("S") || series.equals("T") ? "JZIHGFEDCBA" : "XWUTRQPNMLK";
        return letters.charAt(sum % 11) == m.group(3).charAt(0);
    }

    static boolean amka(String value) {
        String d = digitsOf(value);
        if (d.length() != 11 || !plausibleDate(twoDigits(d, 0), twoDigits(d, 2))) {
            return false;
        }
        return luhn(d, 2, 0);
    }

    private static final Pattern NINO_SHAPE = Pattern.compile("[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][0-9]{6}[A-D]");
    private static final Set<String> NINO_UNUSED = new HashSet<>(Arrays.asList("BG", "GB", "KN", "NK", "NT", "TN", "ZZ"));

    static boolean ukNino(String value) {
        String n = value.replace(" ", "");
        return NINO_SHAPE.matcher(n).matches() && !NINO_UNUSED.contains(n.substring(0, 2));
    }

    /** The vocabulary a pack may reference by name. An unknown name is a load error. */
    static final Map<String, Predicate<String>> NAMED;

    static {
        Map<String, Predicate<String>> named = new HashMap<>();
        named.put("phone", Checksums::phone);
        named.put("iban", Checksums::iban);
        named.put("tckn", Checksums::tckn);
        named.put("cpf", Checksums::cpf);
        named.put("dni", Checksums::dni);
        named.put("bsn", Checksums::bsn);
        named.put("pesel", Checksums::pesel);
        named.put("de_tax_id", Checksums::deTaxId);
        named.put("codice_fiscale", Checksums::codiceFiscale);
        named.put("fr_nir", Checksums::frNir);
        named.put("aadhaar", Checksums::aadhaar);
        named.put("tfn", Checksums::tfn);
        named.put("cn_resident_id", Checksums::cnResidentId);
        named.put("jp_my_number", Checksums::jpMyNumber);
        named.put("us_ssn", Checksums::usSsn);
        named.put("aba", Checksums::aba);
        named.put("nhs", Checksums::nhs);
        named.put("vin", Checksums::vin);
        named.put("cnp", Checksums::cnp);
        named.put("personnummer", Checksums::personnummer);
        named.put("hetu", Checksums::hetu);
        named.put("fodselsnummer", Checksums::fodselsnummer);
        named.put("be_national_number", Checksums::beNationalNumber);
        named.put("pt_nif", Checksums::ptNif);
        named.put("za_id", Checksums::zaId);
        named.put("curp", Checksums::curp);
        named.put("rut", Checksums::rut);
        named.put("cuit", Checksums::cuit);
        named.put("nric", Checksums::nric);
        named.put("amka", Checksums::amka);
        named.put("uk_nino", Checksums::ukNino);
        NAMED = java.util.Collections.unmodifiableMap(named);
    }
}
