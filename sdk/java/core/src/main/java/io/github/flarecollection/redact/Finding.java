package io.github.flarecollection.redact;

/**
 * One thing the scanner would redact, and why. Offsets are UTF-16 code units, the
 * unit of {@link String#length()}; line and column are one-based. A finding made
 * because of a field name has no position: start, end, line and column are -1.
 */
public final class Finding {
    private final String detector;
    private final String label;
    private final String why;
    private final Risk risk;
    private final double confidence;
    private final int start;
    private final int end;
    private final int line;
    private final int column;
    private final String path;
    private final String value;

    Finding(String detector, String label, String why, Risk risk, double confidence,
            int start, int end, int line, int column, String path, String value) {
        this.detector = detector;
        this.label = label;
        this.why = why;
        this.risk = risk;
        this.confidence = confidence;
        this.start = start;
        this.end = end;
        this.line = line;
        this.column = column;
        this.path = path;
        this.value = value;
    }

    Finding withPath(String newPath) {
        return new Finding(detector, label, why, risk, confidence, start, end, line, column, newPath, value);
    }

    /** @return the detector id, such as {@code email} */
    public String detector() {
        return detector;
    }

    /** @return a human-readable name */
    public String label() {
        return label;
    }

    /** @return what an attacker gains from the value */
    public String why() {
        return why;
    }

    /** @return the privacy impact */
    public Risk risk() {
        return risk;
    }

    /** @return the confidence in [0, 1] */
    public double confidence() {
        return confidence;
    }

    /** @return the start offset in UTF-16 code units, or -1 */
    public int start() {
        return start;
    }

    /** @return the end offset (exclusive) in UTF-16 code units, or -1 */
    public int end() {
        return end;
    }

    /** @return the one-based line, or -1 */
    public int line() {
        return line;
    }

    /** @return the one-based column in UTF-16 code units, or -1 */
    public int column() {
        return column;
    }

    /** @return where the value sits in a structure, such as {@code user.email}; empty at the top level */
    public String path() {
        return path;
    }

    /** @return the matched value, only when {@code includeValues} is set; otherwise null */
    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return "Finding{detector=" + detector + ", risk=" + risk.wireName() + ", confidence=" + confidence
            + (start >= 0 ? ", start=" + start + ", end=" + end : "")
            + (path.isEmpty() ? "" : ", path=" + path) + "}";
    }
}
