package io.github.flarecollection.redact;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Keyed transforms (SPEC §8): HMAC-SHA256 fingerprints, the counter-mode byte
 * stream every engine derives identically, and the shape-preserving pseudonym and
 * type-consistent surrogate built on it. None of them is reversible; use a
 * {@link Vault} for that.
 */
public final class Transforms {
    private Transforms() {
    }

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String[] GIVEN_NAMES = {"Alex", "Avery", "Casey", "Emery", "Jordan", "Morgan", "Riley", "Robin"};
    private static final String[] FAMILY_NAMES = {"Arden", "Blake", "Hayes", "Lane", "Parker", "Reed", "Shaw", "Vale"};
    private static final String[] STREETS = {"Cedar", "Harbor", "Juniper", "Maple", "Orchard", "River", "Willow", "Summit"};
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * UTF-8, with a lone surrogate encoded as U+FFFD, which is what JavaScript's
     * {@code TextEncoder} does. {@code String.getBytes} would write {@code ?}
     * instead, and the keyed output would differ from every other engine.
     */
    static byte[] utf8(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length() + 8);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            int code = c;
            if (Character.isHighSurrogate(c) && i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1))) {
                code = Character.toCodePoint(c, text.charAt(++i));
            } else if (Character.isSurrogate(c)) {
                code = 0xFFFD;
            }
            if (code < 0x80) {
                out.write(code);
            } else if (code < 0x800) {
                out.write(0xC0 | (code >> 6));
                out.write(0x80 | (code & 0x3F));
            } else if (code < 0x10000) {
                out.write(0xE0 | (code >> 12));
                out.write(0x80 | ((code >> 6) & 0x3F));
                out.write(0x80 | (code & 0x3F));
            } else {
                out.write(0xF0 | (code >> 18));
                out.write(0x80 | ((code >> 12) & 0x3F));
                out.write(0x80 | ((code >> 6) & 0x3F));
                out.write(0x80 | (code & 0x3F));
            }
        }
        return out.toByteArray();
    }

    static byte[] hmacSha256(String secret, String message) {
        requireSecret(secret);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(utf8(secret), "HmacSHA256"));
            return mac.doFinal(utf8(message));
        } catch (GeneralSecurityException error) {
            throw new FlareRedactException("HMAC-SHA256 is unavailable on this platform", error);
        }
    }

    static void requireSecret(String secret) {
        if (secret == null || secret.isEmpty()) {
            throw new FlareRedactException("a non-empty transformSecret is required for keyed transforms");
        }
    }

    static String hex(byte[] bytes, int count) {
        char[] out = new char[count * 2];
        for (int i = 0; i < count; i++) {
            out[2 * i] = HEX[(bytes[i] >> 4) & 0xF];
            out[2 * i + 1] = HEX[bytes[i] & 0xF];
        }
        return new String(out);
    }

    /**
     * The lowercase hex of the first {@code bytes} bytes of HMAC-SHA256(secret, value).
     *
     * @param secret the transform secret; must not be empty
     * @param value the value to fingerprint
     * @param bytes how many bytes to keep, at most 32
     * @return the fingerprint
     */
    public static String hmacFingerprint(String secret, String value, int bytes) {
        byte[] sum = hmacSha256(secret, value);
        return hex(sum, Math.min(bytes, sum.length));
    }

    /**
     * {@code n} bytes bound to {@code context}: block i is
     * HMAC(secret, context + "\0" + i), concatenated and cut to length.
     *
     * @param secret the transform secret; must not be empty
     * @param context what the bytes are for
     * @param n how many bytes
     * @return the derived bytes
     */
    public static byte[] deriveBytes(String secret, String context, int n) {
        requireSecret(secret);
        byte[] out = new byte[Math.max(0, n)];
        int offset = 0;
        for (int counter = 0; offset < out.length; counter++) {
            byte[] block = hmacSha256(secret, context + "\u0000" + counter);
            int take = Math.min(block.length, out.length - offset);
            System.arraycopy(block, 0, out, offset, take);
            offset += take;
        }
        return out;
    }

    private static String alphabetFor(char c) {
        if (c >= '0' && c <= '9') {
            return DIGITS;
        }
        if (c >= 'a' && c <= 'z') {
            return LOWER;
        }
        if (c >= 'A' && c <= 'Z') {
            return UPPER;
        }
        return null;
    }

    /**
     * A deterministic, keyed, shape-preserving substitution: each ASCII letter or
     * digit becomes another of its class, everything else is kept. Not encryption
     * and not reversible: a stable pseudonym, so joins survive.
     *
     * @param value the value
     * @param secret the transform secret; must not be empty
     * @return the pseudonym
     */
    public static String pseudonymize(String value, String secret) {
        byte[] stream = deriveBytes(secret, "pseudonym:" + value, value.length());
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            String alphabet = alphabetFor(c);
            out.append(alphabet == null ? c : alphabet.charAt((stream[i] & 0xFF) % alphabet.length()));
        }
        return out.toString();
    }

    private static String digitSurrogate(String value, String secret) {
        byte[] stream = deriveBytes(secret, "digits:" + value, value.length());
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            out.append(c >= '0' && c <= '9' ? DIGITS.charAt((stream[i] & 0xFF) % 10) : c);
        }
        return out.toString();
    }

    private static String luhnCheckDigit(String prefix) {
        int sum = 0;
        boolean twice = true;
        for (int i = prefix.length() - 1; i >= 0; i--) {
            char c = prefix.charAt(i);
            if (c < '0' || c > '9') {
                continue;
            }
            int n = c - '0';
            if (twice) {
                n *= 2;
                if (n > 9) {
                    n -= 9;
                }
            }
            sum += n;
            twice = !twice;
        }
        return Integer.toString((10 - sum % 10) % 10);
    }

    private static String cardSurrogate(String value, String secret) {
        String shaped = digitSurrogate(value, secret);
        int last = -1;
        for (int i = 0; i < shaped.length(); i++) {
            if (shaped.charAt(i) >= '0' && shaped.charAt(i) <= '9') {
                last = i;
            }
        }
        if (last < 0) {
            return shaped;
        }
        String prefix = shaped.substring(0, last);
        return prefix + luhnCheckDigit(prefix) + shaped.substring(last + 1);
    }

    /**
     * A deterministic, type-consistent synthetic value for the given detector: an
     * email stays an email, a card stays a Luhn-valid card. Unknown detectors fall
     * back to {@link #pseudonymize}.
     *
     * @param value the value
     * @param detectorId the detector that matched it
     * @param secret the transform secret; must not be empty
     * @return the surrogate
     */
    public static String surrogate(String value, String detectorId, String secret) {
        switch (detectorId) {
            case "email":
                return "user_" + hmacFingerprint(secret, "email:" + value, 6) + "@example.invalid";
            case "credit_card":
                return cardSurrogate(value, secret);
            case "phone":
                return digitSurrogate(value, secret);
            case "person_name": {
                byte[] stream = deriveBytes(secret, "person:" + value, 2);
                return GIVEN_NAMES[(stream[0] & 0xFF) % GIVEN_NAMES.length] + " "
                    + FAMILY_NAMES[(stream[1] & 0xFF) % FAMILY_NAMES.length];
            }
            case "street_address": {
                byte[] stream = deriveBytes(secret, "address:" + value, 3);
                int number = 100 + ((((stream[0] & 0xFF) << 8) | (stream[1] & 0xFF)) % 9800);
                return number + " " + STREETS[(stream[2] & 0xFF) % STREETS.length] + " Street";
            }
            default:
                return pseudonymize(value, secret);
        }
    }
}
