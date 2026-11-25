package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Translates an FRS-1 pattern into {@code java.util.regex} syntax.
 *
 * <p>The translation fixes the places where Java reads the same text differently
 * from the reference engine: {@code .} excludes exactly the JavaScript line
 * terminators, {@code $} is the end of input (Java's also matches before a final
 * line break), {@code \v} is the vertical tab, and inside a class every literal is
 * written as a code point escape, so {@code [}, {@code &&} and {@code #} are never
 * read as Java's class union, intersection or comment syntax. A case-insensitive
 * pattern has its literals and classes spelled out with their whole case orbit
 * (see {@link CaseFolding}) and is compiled without {@code CASE_INSENSITIVE}.
 */
final class PatternTranslator {
    private PatternTranslator() {
    }

    private static final String ANY = "(?s:.)";
    private static final String LETTER = "\\p{L}";
    private static final String DOT = "[^\\n\\r\\x{2028}\\x{2029}]";

    /** A literal, or an escape whose set is opaque ({@code \d}, {@code \p{L}}). */
    private static final class Atom {
        final int code;
        final String opaque;
        final int next;

        Atom(int code, String opaque, int next) {
            this.code = code;
            this.opaque = opaque;
            this.next = next;
        }
    }

    static String translate(String source, boolean insensitive) {
        StringBuilder out = new StringBuilder(source.length() + 16);
        int index = 0;
        while (index < source.length()) {
            char ch = source.charAt(index);
            if (source.startsWith("{{ANY}}", index)) {
                out.append(ANY);
                index += 7;
                continue;
            }
            if (source.startsWith("{{L}}", index)) {
                out.append(LETTER);
                index += 5;
                continue;
            }
            switch (ch) {
                case '[': {
                    index = translateClass(source, index, insensitive, out);
                    continue;
                }
                case '(': {
                    index = copyGroupHeader(source, index, out);
                    continue;
                }
                case ')':
                case '|':
                case '*':
                case '+':
                case '?':
                case '^':
                    out.append(ch);
                    index++;
                    continue;
                case '$':
                    out.append("\\z");
                    index++;
                    continue;
                case '.':
                    out.append(DOT);
                    index++;
                    continue;
                case '{': {
                    int close = quantifierEnd(source, index);
                    if (close > 0) {
                        out.append(source, index, close + 1);
                        index = close + 1;
                        continue;
                    }
                    break;
                }
                default:
                    break;
            }
            Atom atom = readAtom(source, index);
            if (atom.opaque != null) {
                out.append(atom.opaque);
            } else {
                appendLiteral(out, atom.code, insensitive);
            }
            index = atom.next;
        }
        return out.toString();
    }

    /** The index of the closing brace of a {n}, {n,} or {n,m} quantifier, or -1. */
    private static int quantifierEnd(String source, int open) {
        int i = open + 1;
        int digits = i;
        while (i < source.length() && Character.isDigit(source.charAt(i)) && source.charAt(i) < 0x80) {
            i++;
        }
        if (i == digits) {
            return -1;
        }
        if (i < source.length() && source.charAt(i) == ',') {
            i++;
            while (i < source.length() && source.charAt(i) >= '0' && source.charAt(i) <= '9') {
                i++;
            }
        }
        return i < source.length() && source.charAt(i) == '}' ? i : -1;
    }

    private static int copyGroupHeader(String source, int index, StringBuilder out) {
        if (!source.startsWith("(?", index)) {
            out.append('(');
            return index + 1;
        }
        for (String head : new String[] {"(?:", "(?=", "(?!", "(?<=", "(?<!"}) {
            if (source.startsWith(head, index)) {
                out.append(head);
                return index + head.length();
            }
        }
        if (source.startsWith("(?<", index) || source.startsWith("(?P<", index)) {
            int close = source.indexOf('>', index);
            int end = close < 0 ? source.length() : close + 1;
            out.append(source, index, end);
            return end;
        }
        out.append("(?");
        return index + 2;
    }

    private static Atom readAtom(String source, int index) {
        char ch = source.charAt(index);
        if (ch != '\\') {
            int code = source.codePointAt(index);
            return new Atom(code, null, index + Character.charCount(code));
        }
        if (index + 1 >= source.length()) {
            return new Atom('\\', null, index + 1);
        }
        char esc = source.charAt(index + 1);
        switch (esc) {
            case 't':
                return new Atom('\t', null, index + 2);
            case 'n':
                return new Atom('\n', null, index + 2);
            case 'r':
                return new Atom('\r', null, index + 2);
            case 'f':
                return new Atom('\f', null, index + 2);
            case 'v':
                return new Atom(0x0B, null, index + 2);
            case '0':
                return new Atom(0, null, index + 2);
            case 'x': {
                if (index + 4 <= source.length() && isHex(source.charAt(index + 2)) && isHex(source.charAt(index + 3))) {
                    return new Atom(Integer.parseInt(source.substring(index + 2, index + 4), 16), null, index + 4);
                }
                break;
            }
            case 'u': {
                if (index + 6 <= source.length() && Json.hex4(source, index + 2) >= 0) {
                    return new Atom(Json.hex4(source, index + 2), null, index + 6);
                }
                break;
            }
            case 'p':
            case 'P': {
                if (index + 2 < source.length() && source.charAt(index + 2) == '{') {
                    int close = source.indexOf('}', index + 3);
                    if (close >= 0) {
                        return new Atom(-1, source.substring(index, close + 1), close + 1);
                    }
                }
                break;
            }
            default:
                break;
        }
        if ((esc >= 'A' && esc <= 'Z') || (esc >= 'a' && esc <= 'z') || (esc >= '0' && esc <= '9')) {
            return new Atom(-1, source.substring(index, index + 2), index + 2);
        }
        int code = source.codePointAt(index + 1);
        return new Atom(code, null, index + 1 + Character.charCount(code));
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static void appendLiteral(StringBuilder out, int code, boolean insensitive) {
        int[] orbit = insensitive ? CaseFolding.orbit(code) : null;
        if (orbit == null) {
            appendCode(out, code);
            return;
        }
        out.append('[');
        for (int member : orbit) {
            appendClassCode(out, member);
        }
        out.append(']');
    }

    private static void appendCode(StringBuilder out, int code) {
        if ((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') || (code >= '0' && code <= '9')) {
            out.append((char) code);
        } else {
            appendClassCode(out, code);
        }
    }

    private static void appendClassCode(StringBuilder out, int code) {
        out.append("\\x{").append(Integer.toHexString(code)).append('}');
    }

    /** Translate the class starting at {@code start}; returns the index after it. */
    private static int translateClass(String source, int start, boolean insensitive, StringBuilder out) {
        int index = start + 1;
        boolean negated = false;
        if (index < source.length() && source.charAt(index) == '^') {
            negated = true;
            index++;
        }
        List<int[]> ranges = new ArrayList<>();
        List<String> opaque = new ArrayList<>();
        boolean first = true;
        while (index < source.length() && (source.charAt(index) != ']' || first)) {
            first = false;
            Atom low = readAtom(source, index);
            index = low.next;
            if (index + 1 < source.length() && source.charAt(index) == '-' && source.charAt(index + 1) != ']') {
                Atom high = readAtom(source, index + 1);
                index = high.next;
                if (low.opaque != null || high.opaque != null) {
                    // Not a range: a set escape on either side makes '-' a literal.
                    addAtom(low, ranges, opaque);
                    ranges.add(new int[] {'-', '-'});
                    addAtom(high, ranges, opaque);
                } else {
                    ranges.add(new int[] {low.code, high.code});
                }
            } else {
                addAtom(low, ranges, opaque);
            }
        }
        if (index >= source.length()) {
            throw new IllegalArgumentException("unterminated character class");
        }
        index++;

        out.append(negated ? "[^" : "[");
        for (int[] range : ranges) {
            appendClassCode(out, range[0]);
            if (range[1] != range[0]) {
                out.append('-');
                appendClassCode(out, range[1]);
            }
        }
        for (String escape : opaque) {
            out.append(escape);
        }
        if (insensitive) {
            Set<Integer> extra = new TreeSet<>();
            for (int[] range : ranges) {
                CaseFolding.closeRange(range[0], range[1], extra);
            }
            for (int code : extra) {
                boolean inside = false;
                for (int[] range : ranges) {
                    if (code >= range[0] && code <= range[1]) {
                        inside = true;
                        break;
                    }
                }
                if (!inside) {
                    appendClassCode(out, code);
                }
            }
        }
        out.append(']');
        return index;
    }

    private static void addAtom(Atom atom, List<int[]> ranges, List<String> opaque) {
        if (atom.opaque != null) {
            opaque.add(atom.opaque);
        } else {
            ranges.add(new int[] {atom.code, atom.code});
        }
    }

    /** A literal string as a pattern: every code point matched as written, or by its orbit. */
    static String literal(String text, boolean insensitive) {
        StringBuilder out = new StringBuilder(text.length() * 4);
        for (int i = 0; i < text.length(); ) {
            int code = text.codePointAt(i);
            appendLiteral(out, code, insensitive);
            i += Character.charCount(code);
        }
        return out.toString();
    }
}
