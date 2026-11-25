package io.github.flarecollection.redact;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * How a {@link Vault} mints placeholders.
 *
 * <p>Placeholders are opaque by default: {@code [FR_EMAIL_<24 random hex digits>]},
 * so the text that leaves your process does not also disclose how many distinct
 * people or secrets it involves. Readable placeholders ({@code [EMAIL_1]}) are
 * predictable; use them only for trusted local debugging.
 */
public final class VaultOptions {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static final VaultOptions OPAQUE = new VaultOptions(VaultOptions::opaque);
    private static final VaultOptions READABLE = new VaultOptions(VaultOptions::readable);

    final BiFunction<String, Integer, String> placeholder;

    private VaultOptions(BiFunction<String, Integer, String> placeholder) {
        this.placeholder = placeholder;
    }

    /** @return opaque placeholders, the default */
    public static VaultOptions defaults() {
        return OPAQUE;
    }

    /** @return opaque placeholders: {@code [FR_<ID>_<24 hex digits>]} from a CSPRNG */
    public static VaultOptions opaquePlaceholders() {
        return OPAQUE;
    }

    /** @return counted placeholders such as {@code [EMAIL_1]}; predictable, local debugging only */
    public static VaultOptions readablePlaceholders() {
        return READABLE;
    }

    /**
     * Your own placeholder format. It receives the detector id and a per-detector
     * count starting at 1, and must never return the same token for two different
     * values: the vault refuses a duplicate rather than restore the wrong secret.
     *
     * @param format the placeholder function
     * @return the options
     */
    public static VaultOptions customPlaceholders(BiFunction<String, Integer, String> format) {
        return new VaultOptions(Objects.requireNonNull(format, "format"));
    }

    private static String opaque(String detectorId, Integer index) {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        char[] hex = new char[24];
        for (int i = 0; i < bytes.length; i++) {
            hex[2 * i] = HEX[(bytes[i] >> 4) & 0xF];
            hex[2 * i + 1] = HEX[bytes[i] & 0xF];
        }
        return "[FR_" + detectorId.toUpperCase(Locale.ROOT) + "_" + new String(hex) + "]";
    }

    private static String readable(String detectorId, Integer index) {
        return "[" + detectorId.toUpperCase(Locale.ROOT) + "_" + index + "]";
    }
}
