package io.github.flarecollection.redact;

import java.util.Collections;
import java.util.Map;

/** Counts of findings by detector and by risk, with no values: safe to log. */
public final class Summary {
    private final int total;
    private final Map<String, Integer> byDetector;
    private final Map<String, Integer> byRisk;

    Summary(int total, Map<String, Integer> byDetector, Map<String, Integer> byRisk) {
        this.total = total;
        this.byDetector = Collections.unmodifiableMap(byDetector);
        this.byRisk = Collections.unmodifiableMap(byRisk);
    }

    /** @return the number of findings */
    public int total() {
        return total;
    }

    /** @return findings per detector id */
    public Map<String, Integer> byDetector() {
        return byDetector;
    }

    /** @return findings per risk wire name */
    public Map<String, Integer> byRisk() {
        return byRisk;
    }

    @Override
    public String toString() {
        return "Summary{total=" + total + ", byDetector=" + byDetector + ", byRisk=" + byRisk + "}";
    }
}
