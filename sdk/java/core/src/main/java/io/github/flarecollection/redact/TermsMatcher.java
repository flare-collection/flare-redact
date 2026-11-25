package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The terms scan of SPEC §9, written out rather than left to a lookbehind:
 * {@code java.util.regex} reads the character before a position one UTF-16 unit
 * at a time, so a letter outside the BMP would not count as a neighbour. A
 * candidate position is one where some term matches; it is taken when the code
 * point before it is not a word character and, trying the terms in order, one of
 * them ends before a non-word code point. Otherwise the scan moves on by one
 * character.
 */
final class TermsMatcher {
    private final Pattern any;
    private final List<Pattern> each;
    private final List<String> replace;

    private TermsMatcher(Pattern any, List<Pattern> each, List<String> replace) {
        this.any = any;
        this.each = each;
        this.replace = replace;
    }

    static Detector detector(List<Term> terms, boolean caseSensitive) {
        List<Term> ordered = new ArrayList<>();
        for (Term term : terms) {
            if (term != null && !term.term().isEmpty()) {
                ordered.add(term);
            }
        }
        if (ordered.isEmpty()) {
            return null;
        }
        // Longest first in characters; the sort is stable, so ties keep the caller's order.
        Collections.sort(ordered, (a, b) -> Integer.compare(
            b.term().codePointCount(0, b.term().length()), a.term().codePointCount(0, a.term().length())));

        List<Pattern> each = new ArrayList<>();
        List<String> replace = new ArrayList<>();
        StringBuilder alternation = new StringBuilder();
        for (Term term : ordered) {
            String source = PatternTranslator.literal(term.term(), !caseSensitive);
            each.add(Pattern.compile(source));
            replace.add(term.replace() == null ? "***" : term.replace());
            if (alternation.length() > 0) {
                alternation.append('|');
            }
            alternation.append(source);
        }
        Pattern any = Pattern.compile(alternation.toString());
        TermsMatcher matcher = new TermsMatcher(any, Collections.unmodifiableList(each),
            Collections.unmodifiableList(replace));

        Detector.Builder b = new Detector.Builder();
        b.id = "custom_term";
        b.label = "Custom term";
        b.why = "A term you configured as sensitive.";
        b.risk = Risk.HIGH;
        b.confidence = 0.92;
        b.defaultOn = true;
        b.tags.add("custom");
        b.pattern = any;
        b.terms = matcher;
        b.mask = matcher::replacementFor;
        return new Detector(b);
    }

    /** The boundary class of SPEC §9: letters, combining marks, numbers and {@code _}. */
    static boolean isWord(int code) {
        if (code == '_') {
            return true;
        }
        switch (Character.getType(code)) {
            case Character.UPPERCASE_LETTER:
            case Character.LOWERCASE_LETTER:
            case Character.TITLECASE_LETTER:
            case Character.MODIFIER_LETTER:
            case Character.OTHER_LETTER:
            case Character.NON_SPACING_MARK:
            case Character.ENCLOSING_MARK:
            case Character.COMBINING_SPACING_MARK:
            case Character.DECIMAL_DIGIT_NUMBER:
            case Character.LETTER_NUMBER:
            case Character.OTHER_NUMBER:
                return true;
            default:
                return false;
        }
    }

    List<int[]> findAll(String subject) {
        List<int[]> out = new ArrayList<>();
        Matcher search = any.matcher(subject);
        int position = 0;
        while (position < subject.length() && search.find(position)) {
            int start = search.start();
            int width = Character.charCount(subject.codePointAt(start));
            if (start > 0 && isWord(subject.codePointBefore(start))) {
                position = start + width;
                continue;
            }
            int end = -1;
            for (Pattern term : each) {
                Matcher m = term.matcher(subject).region(start, subject.length());
                m.useTransparentBounds(true);
                if (!m.lookingAt() || m.end() == start) {
                    continue;
                }
                int candidate = m.end();
                if (candidate < subject.length() && isWord(subject.codePointAt(candidate))) {
                    continue;
                }
                end = candidate;
                break;
            }
            if (end < 0) {
                position = start + width;
                continue;
            }
            out.add(new int[] {start, end});
            position = end;
        }
        return out;
    }

    /** The replacement of the first term, in matching order, that matches {@code value} exactly. */
    String replacementFor(String value) {
        for (int i = 0; i < each.size(); i++) {
            if (each.get(i).matcher(value).matches()) {
                return replace.get(i);
            }
        }
        return "***";
    }
}
