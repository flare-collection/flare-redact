package io.github.flarecollection.redact;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.UUID;

/**
 * The text a value under a sensitive key is replaced as (SPEC §9): a number as
 * its decimal text, {@code byte[]} as lowercase hex, a {@link UUID} in its
 * canonical form, {@code char[]} and {@link Character} as their characters. Every engine writes the same text, so
 * hash and vault modes agree across languages.
 */
final class SensitiveValues {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private SensitiveValues() {
    }

    /**
     * @param value any value
     * @return its replacement text, or {@code null} when it is not a number,
     *     binary data or characters
     */
    static String text(Object value) {
        if (value instanceof Double) {
            return jsFloat((Double) value, false);
        }
        if (value instanceof Float) {
            return jsFloat((Float) value, true);
        }
        if (value instanceof BigDecimal) {
            BigDecimal decimal = (BigDecimal) value;
            if (decimal.signum() == 0 || decimal.stripTrailingZeros().scale() <= 0) {
                return decimal.toBigInteger().toString();
            }
            return jsFloat(decimal.doubleValue(), false);
        }
        if (value instanceof Number) {
            return value.toString();
        }
        if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            char[] out = new char[bytes.length * 2];
            for (int i = 0; i < bytes.length; i++) {
                out[2 * i] = HEX[(bytes[i] >> 4) & 0xf];
                out[2 * i + 1] = HEX[bytes[i] & 0xf];
            }
            return new String(out);
        }
        if (value instanceof char[]) {
            return new String((char[]) value);
        }
        if (value instanceof Character || value instanceof UUID) {
            return value.toString();
        }
        return null;
    }

    /**
     * @param value a value under a sensitive key that is neither a container nor
     *     one of the types {@link #text} knows
     * @return whether it is kept there: a boolean or a point in time or span of
     *     time, which cannot carry a credential
     */
    static boolean kept(Object value) {
        return value instanceof Boolean || value instanceof java.util.Date || value instanceof java.util.Calendar
            || value instanceof java.time.temporal.TemporalAccessor || value instanceof java.time.temporal.TemporalAmount;
    }

    /**
     * A floating point number as ECMAScript's {@code Number::toString} writes it:
     * the shortest digits that round-trip, in full from 1e-6 up to 1e21 and in
     * exponent form outside.
     *
     * @param value the number
     * @param single whether it is a {@code float}, whose shortest digits are fewer
     * @return its text
     */
    static String jsFloat(double value, boolean single) {
        if (Double.isNaN(value)) {
            return "NaN";
        }
        if (Double.isInfinite(value)) {
            return value > 0 ? "Infinity" : "-Infinity";
        }
        if (value == 0) {
            return "0";
        }
        String sign = value < 0 ? "-" : "";
        double magnitude = Math.abs(value);
        // The exact binary value, rounded to the fewest digits that still read
        // back as the same number; that rounding is also the closest candidate.
        BigDecimal exact = new BigDecimal(magnitude);
        BigDecimal shortest = exact;
        for (int precision = 1; precision <= 17; precision++) {
            BigDecimal candidate = exact.round(new MathContext(precision, RoundingMode.HALF_EVEN));
            boolean same = single
                ? candidate.floatValue() == (float) magnitude
                : candidate.doubleValue() == magnitude;
            if (same) {
                shortest = candidate;
                break;
            }
        }
        shortest = shortest.stripTrailingZeros();
        String digits = shortest.unscaledValue().toString();
        int k = digits.length();
        int n = k - shortest.scale();
        if (k <= n && n <= 21) {
            return sign + digits + "0".repeat(n - k);
        }
        if (0 < n && n <= 21) {
            return sign + digits.substring(0, n) + "." + digits.substring(n);
        }
        if (-6 < n && n <= 0) {
            return sign + "0." + "0".repeat(-n) + digits;
        }
        String rest = k > 1 ? "." + digits.substring(1) : "";
        int power = n - 1;
        return sign + digits.charAt(0) + rest + "e" + (power >= 0 ? "+" : "-") + Math.abs(power);
    }
}
