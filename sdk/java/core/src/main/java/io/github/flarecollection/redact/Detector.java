package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** One compiled rule: what it matches, how it is validated, how a match is replaced. */
public final class Detector {
    final String id;
    final String label;
    final String why;
    final Risk risk;
    final double confidence;
    final int priority;
    final boolean defaultOn;
    final List<String> tags;
    final boolean refine;

    final Pattern pattern;
    final int capture;
    final String before;
    final String after;
    final Pattern prefilter;
    final List<Pattern> reject;
    final List<Predicate<String>> validators;
    final Function<String, String> mask;
    final Pattern contextPositive;
    final Pattern contextNegative;
    final int contextWindow;
    final TermsMatcher terms;
    final BitSet first;

    Detector(Builder b) {
        this.id = b.id;
        this.label = b.label;
        this.why = b.why;
        this.risk = b.risk;
        this.confidence = b.confidence;
        this.priority = b.priority;
        this.defaultOn = b.defaultOn;
        this.tags = Collections.unmodifiableList(new ArrayList<>(b.tags));
        this.refine = b.refine;
        this.pattern = b.pattern;
        this.capture = b.capture;
        this.before = b.before;
        this.after = b.after;
        this.prefilter = b.prefilter;
        this.reject = Collections.unmodifiableList(new ArrayList<>(b.reject));
        this.validators = Collections.unmodifiableList(new ArrayList<>(b.validators));
        this.mask = b.mask;
        this.contextPositive = b.contextPositive;
        this.contextNegative = b.contextNegative;
        this.contextWindow = b.contextWindow;
        this.terms = b.terms;
        this.first = b.first;
    }

    static final class Builder {
        String id;
        String label;
        String why;
        Risk risk;
        double confidence;
        int priority;
        boolean defaultOn;
        List<String> tags = new ArrayList<>();
        boolean refine;
        Pattern pattern;
        int capture;
        String before;
        String after;
        Pattern prefilter;
        List<Pattern> reject = new ArrayList<>();
        List<Predicate<String>> validators = new ArrayList<>();
        Function<String, String> mask = value -> "***";
        Pattern contextPositive;
        Pattern contextNegative;
        int contextWindow = 80;
        TermsMatcher terms;
        BitSet first;
    }

    /** The detector reported for a value found under a sensitive field name. */
    static final Detector SENSITIVE_KEY;

    static {
        Builder b = new Builder();
        b.id = "sensitive_key";
        b.label = "Sensitive field";
        b.why = "A value stored under a field name that is sensitive by convention.";
        b.risk = Risk.CRITICAL;
        b.confidence = 0.98;
        b.defaultOn = true;
        SENSITIVE_KEY = new Detector(b);
    }

    /** @return the stable identifier, used in findings and in {@code label} mode */
    public String id() {
        return id;
    }

    /** @return a human-readable name */
    public String label() {
        return label;
    }

    /** @return one sentence a reader can act on: what an attacker gains */
    public String why() {
        return why;
    }

    /** @return the privacy impact */
    public Risk risk() {
        return risk;
    }

    /** @return the base confidence before contextual adjustment */
    public double confidence() {
        return confidence;
    }

    /** @return the explicit overlap priority; higher wins */
    public int priority() {
        return priority;
    }

    /** @return whether the detector runs unless disabled */
    public boolean isDefault() {
        return defaultOn;
    }

    /** @return the selectable groups for {@code enable}, {@code disable} and {@code only} */
    public List<String> tags() {
        return tags;
    }

    /** @return whether the learned classifier may adjust this detector's confidence */
    public boolean refine() {
        return refine;
    }

    /**
     * @param selector a detector id or tag
     * @return whether {@code selector} names this detector or one of its tags
     */
    public boolean matchesSelector(String selector) {
        return id.equals(selector) || tags.contains(selector);
    }

    /** The UTF-16 spans of the captured group of every match in {@code subject}. */
    List<int[]> spans(String subject) {
        if (terms != null) {
            return terms.findAll(subject);
        }
        List<int[]> out = new ArrayList<>();
        Matcher matcher = pattern.matcher(subject);
        int length = subject.length();
        int from = 0;
        if (first != null) {
            // Try only the positions a match can start at (see FirstSet).
            while (from < length) {
                char c = subject.charAt(from);
                if (!first.get(c) || (Character.isLowSurrogate(c) && from > 0
                        && Character.isHighSurrogate(subject.charAt(from - 1)))) {
                    from++;
                    continue;
                }
                matcher.region(from, length);
                if (!matcher.lookingAt()) {
                    from++;
                    continue;
                }
                out.add(new int[] {matcher.start(capture), matcher.end(capture)});
                from = matcher.end() > from ? matcher.end() : from + 1;
            }
            return out;
        }
        while (from <= length && matcher.find(from)) {
            int start = matcher.start();
            int end = matcher.end();
            if (start > 0 && start < length && Character.isLowSurrogate(subject.charAt(start))
                    && Character.isHighSurrogate(subject.charAt(start - 1))) {
                // java.util.regex may try a match from the middle of a surrogate
                // pair; the reference engine moves by code point and never does.
                from = start + 1;
                continue;
            }
            out.add(new int[] {matcher.start(capture), matcher.end(capture)});
            from = end > start ? end : start + 1;
        }
        return out;
    }

    boolean boundaryOk(String subject, int start, int end) {
        if (before != null && start > 0 && before.indexOf(subject.charAt(start - 1)) >= 0) {
            return false;
        }
        return after == null || end >= subject.length() || after.indexOf(subject.charAt(end)) < 0;
    }

    boolean rejects(String value) {
        for (Pattern pattern : reject) {
            if (pattern.matcher(value).lookingAt()) {
                return true;
            }
        }
        return false;
    }

    boolean validates(String value) {
        for (Predicate<String> validator : validators) {
            if (!validator.test(value)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return "Detector{" + id + ", risk=" + risk.wireName() + ", default=" + defaultOn + "}";
    }
}
