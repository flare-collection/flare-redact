package io.github.flarecollection.redact;

import java.util.Locale;

/** How a matched value is replaced (SPEC §7). */
public enum Mode {
    /** The detector's own mask strategy, such as {@code ***} or {@code **** 4242}. */
    MASK,
    /** {@code [REDACTED:<detector id>]}. */
    LABEL,
    /** {@code <detector id>_<keyed fingerprint>}; needs a transform secret. */
    HASH,
    /** A keyed, shape-preserving substitution; needs a transform secret. */
    PSEUDONYM,
    /** A keyed, type-consistent synthetic value; needs a transform secret. */
    SURROGATE;

    /** @return the wire name, such as {@code mask} or {@code pseudonym} */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * @param name a wire name
     * @return the mode it names
     * @throws IllegalArgumentException for an unknown name
     */
    public static Mode fromWire(String name) {
        for (Mode mode : values()) {
            if (mode.wireName().equals(name)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("unknown mode \"" + name + "\"");
    }
}
