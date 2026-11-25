package io.github.flarecollection.redact;

import java.util.BitSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * The UTF-16 units a match of an FRS-1 pattern can start with.
 *
 * <p>{@code java.util.regex} tries every alternative of a pattern at every
 * position of the subject. Knowing which units can begin a match lets the scan
 * skip the positions where none can, which is most of them for a pattern such as
 * an IBAN (an upper-case letter) or an IPv6 address (a hex digit or a colon). The
 * set is an over-approximation: when the analysis cannot be sure (an unbounded
 * set escape, a negated class it cannot bound), it answers "any unit", and the
 * scan falls back to trying every position. It never answers too little, so it
 * never changes what is found.
 */
final class FirstSet {
    private static final int UNITS = 0x10000;

    private static volatile BitSet letters;

    private final String source;
    private final boolean insensitive;
    private int index;

    private FirstSet(String source, boolean insensitive) {
        this.source = source;
        this.insensitive = insensitive;
    }

    /** The result of analysing one alternation, branch or atom. */
    private static final class Result {
        BitSet units = new BitSet(UNITS);
        boolean any;
        boolean nullable;
    }

    /**
     * @param source a portable FRS-1 pattern
     * @param insensitive whether it is matched case-insensitively
     * @return the possible first units, or null when any unit may start a match
     */
    static BitSet of(String source, boolean insensitive) {
        try {
            FirstSet analysis = new FirstSet(source, insensitive);
            Result result = analysis.alternation();
            if (analysis.index != source.length() || result.any || result.nullable) {
                return null;
            }
            return result.units;
        } catch (RuntimeException error) {
            return null;
        }
    }

    private Result alternation() {
        Result out = branch();
        while (index < source.length() && source.charAt(index) == '|') {
            index++;
            Result next = branch();
            out.units.or(next.units);
            out.any |= next.any;
            out.nullable |= next.nullable;
        }
        return out;
    }

    private Result branch() {
        Result out = new Result();
        out.nullable = true;
        while (index < source.length() && source.charAt(index) != '|' && source.charAt(index) != ')') {
            Result atom = quantified();
            if (out.nullable) {
                out.units.or(atom.units);
                out.any |= atom.any;
                out.nullable = atom.nullable;
            }
        }
        return out;
    }

    private Result quantified() {
        Result atom = atom();
        if (index < source.length()) {
            char c = source.charAt(index);
            if (c == '*' || c == '?') {
                atom.nullable = true;
                index++;
            } else if (c == '+') {
                index++;
            } else if (c == '{') {
                int close = source.indexOf('}', index);
                String body = close > index ? source.substring(index + 1, close) : "";
                if (body.matches("[0-9]+(,[0-9]*)?")) {
                    int min = Integer.parseInt(body.split(",", -1)[0]);
                    if (min == 0) {
                        atom.nullable = true;
                    }
                    index = close + 1;
                }
            }
            if (index < source.length() && source.charAt(index) == '?') {
                index++;
            }
        }
        return atom;
    }

    private Result atom() {
        Result out = new Result();
        if (source.startsWith("{{ANY}}", index)) {
            index += 7;
            out.any = true;
            return out;
        }
        if (source.startsWith("{{L}}", index)) {
            index += 5;
            out.units.or(letters());
            return out;
        }
        char c = source.charAt(index);
        if (c == '(') {
            index += source.startsWith("(?:", index) ? 3 : 1;
            Result inner = alternation();
            if (index >= source.length() || source.charAt(index) != ')') {
                throw new IllegalArgumentException("unbalanced group");
            }
            index++;
            return inner;
        }
        if (c == '.') {
            index++;
            out.any = true;
            return out;
        }
        if (c == '[') {
            return charClass();
        }
        int code = literal();
        if (code < 0) {
            out.any = true;
        } else {
            addCode(out.units, code);
        }
        return out;
    }

    /** One literal at {@code index}, escapes decoded; -1 for a set escape. */
    private int literal() {
        char c = source.charAt(index);
        if (c != '\\') {
            int code = source.codePointAt(index);
            index += Character.charCount(code);
            return code;
        }
        char esc = source.charAt(index + 1);
        switch (esc) {
            case 't':
                index += 2;
                return '\t';
            case 'n':
                index += 2;
                return '\n';
            case 'r':
                index += 2;
                return '\r';
            case 'f':
                index += 2;
                return '\f';
            case 'v':
                index += 2;
                return 0x0B;
            case '0':
                index += 2;
                return 0;
            case 'x':
                if (index + 4 <= source.length()) {
                    int value = Integer.parseInt(source.substring(index + 2, index + 4), 16);
                    index += 4;
                    return value;
                }
                throw new IllegalArgumentException("short \\x escape");
            case 'u': {
                int value = Json.hex4(source, index + 2);
                if (value < 0) {
                    throw new IllegalArgumentException("bad \\u escape");
                }
                index += 6;
                return value;
            }
            default:
                if ((esc >= 'A' && esc <= 'Z') || (esc >= 'a' && esc <= 'z') || (esc >= '0' && esc <= '9')) {
                    index += 2;
                    return -1;
                }
                int code = source.codePointAt(index + 1);
                index += 1 + Character.charCount(code);
                return code;
        }
    }

    private Result charClass() {
        Result out = new Result();
        index++;
        boolean negated = index < source.length() && source.charAt(index) == '^';
        if (negated) {
            index++;
        }
        Set<Integer> codes = new TreeSet<>();
        BitSet members = new BitSet(UNITS);
        boolean astral = false;
        boolean first = true;
        while (index < source.length() && (source.charAt(index) != ']' || first)) {
            first = false;
            int low = literal();
            int high = low;
            if (index + 1 < source.length() && source.charAt(index) == '-' && source.charAt(index + 1) != ']') {
                index++;
                high = literal();
            }
            if (low < 0 || high < 0) {
                // A set escape inside a class: give up on bounding it.
                out.any = true;
                continue;
            }
            if (high - low > 0x3000) {
                out.any = true;
                continue;
            }
            for (int code = low; code <= high; code++) {
                codes.add(code);
            }
        }
        if (index >= source.length()) {
            throw new IllegalArgumentException("unterminated class");
        }
        index++;
        if (out.any) {
            return out;
        }
        if (insensitive) {
            Set<Integer> closed = new TreeSet<>(codes);
            for (int code : codes) {
                CaseFolding.closeRange(code, code, closed);
            }
            codes = closed;
        }
        for (int code : codes) {
            if (code >= UNITS) {
                astral = true;
            } else {
                members.set(code);
            }
        }
        if (negated) {
            // Everything outside the class can start a match, astral code points included.
            BitSet complement = new BitSet(UNITS);
            complement.set(0, UNITS);
            complement.andNot(members);
            complement.set(0xD800, 0xDC00);
            out.units = complement;
            return out;
        }
        out.units = members;
        if (astral) {
            out.units.set(0xD800, 0xDC00);
        }
        return out;
    }

    private void addCode(BitSet units, int code) {
        int[] orbit = insensitive ? CaseFolding.orbit(code) : null;
        if (orbit == null) {
            orbit = new int[] {code};
        }
        for (int member : orbit) {
            if (member >= UNITS) {
                units.set(Character.highSurrogate(member));
            } else {
                units.set(member);
            }
        }
    }

    private static BitSet letters() {
        BitSet cached = letters;
        if (cached == null) {
            cached = new BitSet(UNITS);
            for (int code = 0; code < UNITS; code++) {
                if (Character.isLetter(code)) {
                    cached.set(code);
                }
            }
            cached.set(0xD800, 0xDC00);
            letters = cached;
        }
        return cached;
    }
}
