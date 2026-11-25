package io.github.flarecollection.redact;

import java.util.Objects;

/** A word or phrase of your own to always catch, with an optional replacement (SPEC §9). */
public final class Term {
    private final String term;
    private final String replace;

    private Term(String term, String replace) {
        this.term = Objects.requireNonNull(term, "term");
        this.replace = replace;
    }

    /**
     * @param term the literal to catch
     * @return a term replaced by {@code ***}
     */
    public static Term of(String term) {
        return new Term(term, null);
    }

    /**
     * @param term the literal to catch
     * @param replace its replacement
     * @return a term with its own replacement
     */
    public static Term of(String term, String replace) {
        return new Term(term, replace);
    }

    /** @return the literal */
    public String term() {
        return term;
    }

    /** @return the replacement, or null for {@code ***} */
    public String replace() {
        return replace;
    }
}
