package io.github.flarecollection.redact;

import java.util.Locale;

/** Privacy impact of a detector, used to resolve overlapping matches (SPEC §5). */
public enum Risk {
    /** Little consequence on its own. */
    LOW(1),
    /** Identifying in combination with other data. */
    MEDIUM(1e3),
    /** Identifying or exploitable on its own. */
    HIGH(1e6),
    /** A credential or a value that must never leave the process. */
    CRITICAL(1e9);

    private final double weight;

    Risk(double weight) {
        this.weight = weight;
    }

    double weight() {
        return weight;
    }

    /** @return the wire name: {@code low}, {@code medium}, {@code high} or {@code critical} */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    static Risk fromWire(String name) {
        for (Risk risk : values()) {
            if (risk.wireName().equals(name)) {
                return risk;
            }
        }
        return null;
    }
}
