package io.github.flarecollection.redact;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, strict JSON reader and writer (RFC 8259), so the core library needs no
 * dependency to load a detector pack, read wire options or restore into JSON
 * text.
 *
 * <p>Objects read as {@link LinkedHashMap} (member order kept), arrays as
 * {@link ArrayList}, numbers as {@link Long} when they are integers that fit and
 * {@link Double} otherwise, and {@code true}/{@code false}/{@code null} as
 * themselves. Strings may hold lone surrogates written as {@code \}{@code uXXXX}
 * escapes, exactly as JavaScript's {@code JSON.parse} allows.
 */
public final class Json {
    /** Nesting deeper than this is refused rather than risking the thread's stack. */
    public static final int MAX_DEPTH = 1000;

    private final String text;
    private int index;

    private Json(String text) {
        this.text = text;
    }

    /**
     * Parse a complete JSON document.
     *
     * @param text the document
     * @return the value it denotes
     * @throws IllegalArgumentException when the text is not valid JSON
     */
    public static Object parse(String text) {
        Json reader = new Json(text);
        reader.skipWhitespace();
        Object value = reader.readValue(0);
        reader.skipWhitespace();
        if (reader.index != text.length()) {
            throw reader.error("unexpected content after the document");
        }
        return value;
    }

    /**
     * Whether {@code text} is a complete, valid JSON document. Never throws, and
     * checks without building values or recursing, so deeply nested input cannot
     * exhaust the stack.
     *
     * @param text any string
     * @return true when the whole string parses as JSON
     */
    public static boolean isValid(String text) {
        return Validator.valid(text);
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("invalid JSON at offset " + index + ": " + message);
    }

    private void skipWhitespace() {
        while (index < text.length()) {
            char c = text.charAt(index);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                index++;
            } else {
                break;
            }
        }
    }

    private Object readValue(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("nesting is deeper than " + MAX_DEPTH);
        }
        if (index >= text.length()) {
            throw error("unexpected end of input");
        }
        char c = text.charAt(index);
        switch (c) {
            case '{':
                return readObject(depth);
            case '[':
                return readArray(depth);
            case '"':
                return readString();
            case 't':
                return readLiteral("true", Boolean.TRUE);
            case 'f':
                return readLiteral("false", Boolean.FALSE);
            case 'n':
                return readLiteral("null", null);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return readNumber();
                }
                throw error("unexpected character");
        }
    }

    private Object readLiteral(String word, Object value) {
        if (!text.startsWith(word, index)) {
            throw error("unexpected character");
        }
        index += word.length();
        return value;
    }

    private Map<String, Object> readObject(int depth) {
        index++;
        Map<String, Object> out = new LinkedHashMap<>();
        skipWhitespace();
        if (index < text.length() && text.charAt(index) == '}') {
            index++;
            return out;
        }
        while (true) {
            skipWhitespace();
            if (index >= text.length() || text.charAt(index) != '"') {
                throw error("expected a member name");
            }
            String key = readString();
            skipWhitespace();
            if (index >= text.length() || text.charAt(index) != ':') {
                throw error("expected ':'");
            }
            index++;
            skipWhitespace();
            out.put(key, readValue(depth + 1));
            skipWhitespace();
            if (index >= text.length()) {
                throw error("unterminated object");
            }
            char c = text.charAt(index++);
            if (c == '}') {
                return out;
            }
            if (c != ',') {
                throw error("expected ',' or '}'");
            }
        }
    }

    private List<Object> readArray(int depth) {
        index++;
        List<Object> out = new ArrayList<>();
        skipWhitespace();
        if (index < text.length() && text.charAt(index) == ']') {
            index++;
            return out;
        }
        while (true) {
            skipWhitespace();
            out.add(readValue(depth + 1));
            skipWhitespace();
            if (index >= text.length()) {
                throw error("unterminated array");
            }
            char c = text.charAt(index++);
            if (c == ']') {
                return out;
            }
            if (c != ',') {
                throw error("expected ',' or ']'");
            }
        }
    }

    private String readString() {
        index++;
        StringBuilder out = null;
        int start = index;
        while (true) {
            if (index >= text.length()) {
                throw error("unterminated string");
            }
            char c = text.charAt(index);
            if (c == '"') {
                String tail = text.substring(start, index);
                index++;
                return out == null ? tail : out.append(tail).toString();
            }
            if (c < 0x20) {
                throw error("unescaped control character in a string");
            }
            if (c != '\\') {
                index++;
                continue;
            }
            if (out == null) {
                out = new StringBuilder();
            }
            out.append(text, start, index);
            if (index + 1 >= text.length()) {
                throw error("unterminated escape");
            }
            char escape = text.charAt(index + 1);
            index += 2;
            switch (escape) {
                case '"':
                case '\\':
                case '/':
                    out.append(escape);
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    int unit = hex4(text, index);
                    if (unit < 0) {
                        throw error("invalid \\u escape");
                    }
                    out.append((char) unit);
                    index += 4;
                    break;
                default:
                    throw error("invalid escape");
            }
            start = index;
        }
    }

    static int hex4(String text, int at) {
        if (at + 4 > text.length()) {
            return -1;
        }
        int value = 0;
        for (int i = at; i < at + 4; i++) {
            int digit = Character.digit(text.charAt(i), 16);
            if (digit < 0 || text.charAt(i) > 'f') {
                return -1;
            }
            value = value * 16 + digit;
        }
        return value;
    }

    private Object readNumber() {
        int start = index;
        if (text.charAt(index) == '-') {
            index++;
        }
        if (index >= text.length()) {
            throw error("invalid number");
        }
        if (text.charAt(index) == '0') {
            index++;
        } else if (text.charAt(index) >= '1' && text.charAt(index) <= '9') {
            while (index < text.length() && isDigit(text.charAt(index))) {
                index++;
            }
        } else {
            throw error("invalid number");
        }
        boolean integral = true;
        if (index < text.length() && text.charAt(index) == '.') {
            integral = false;
            index++;
            int digits = index;
            while (index < text.length() && isDigit(text.charAt(index))) {
                index++;
            }
            if (index == digits) {
                throw error("invalid number");
            }
        }
        if (index < text.length() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
            integral = false;
            index++;
            if (index < text.length() && (text.charAt(index) == '+' || text.charAt(index) == '-')) {
                index++;
            }
            int digits = index;
            while (index < text.length() && isDigit(text.charAt(index))) {
                index++;
            }
            if (index == digits) {
                throw error("invalid number");
            }
        }
        String literal = text.substring(start, index);
        if (integral) {
            BigInteger big = new BigInteger(literal);
            if (big.bitLength() < 64) {
                return big.longValue();
            }
        }
        return Double.parseDouble(literal);
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /**
     * Write a value as compact JSON. Maps, collections, arrays, strings, numbers,
     * booleans and null are supported; anything else is written as its string form.
     *
     * @param value the value
     * @return its JSON text
     */
    public static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, 0);
        return out.toString();
    }

    private static void write(StringBuilder out, Object value, int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("value nests deeper than " + MAX_DEPTH + " levels");
        }
        if (value == null) {
            out.append("null");
        } else if (value instanceof CharSequence) {
            quote(out, value.toString());
        } else if (value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Number) {
            out.append(number((Number) value));
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                quote(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue(), depth + 1);
            }
            out.append('}');
        } else if (value instanceof Collection) {
            out.append('[');
            boolean first = true;
            for (Object item : (Collection<?>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, item, depth + 1);
            }
            out.append(']');
        } else if (value instanceof Object[]) {
            out.append('[');
            Object[] items = (Object[]) value;
            for (int i = 0; i < items.length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(out, items[i], depth + 1);
            }
            out.append(']');
        } else {
            quote(out, value.toString());
        }
    }

    private static String number(Number value) {
        if (value instanceof Double || value instanceof Float) {
            double d = value.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                return "null";
            }
            if (d == Math.rint(d) && Math.abs(d) < 1e21) {
                return new BigDecimal(d).toPlainString();
            }
            return Double.toString(d);
        }
        if (value instanceof BigDecimal) {
            return ((BigDecimal) value).toString();
        }
        return value.toString();
    }

    /**
     * Append {@code value} as a JSON string literal, quotes included.
     *
     * @param out the destination
     * @param value the string
     */
    static void quote(StringBuilder out, String value) {
        out.append('"');
        out.append(escape(value));
        out.append('"');
    }

    /**
     * The content of a JSON string literal for {@code value}, without the quotes
     * (SPEC §11): the quote, the backslash, control characters and lone
     * surrogates are escaped, nothing else.
     *
     * @param value any string
     * @return the escaped form
     */
    public static String escape(String value) {
        StringBuilder out = null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            String replacement = null;
            switch (c) {
                case '"':
                    replacement = "\\\"";
                    break;
                case '\\':
                    replacement = "\\\\";
                    break;
                case '\b':
                    replacement = "\\b";
                    break;
                case '\t':
                    replacement = "\\t";
                    break;
                case '\n':
                    replacement = "\\n";
                    break;
                case '\f':
                    replacement = "\\f";
                    break;
                case '\r':
                    replacement = "\\r";
                    break;
                default:
                    if (c < 0x20 || isLoneSurrogate(value, i)) {
                        replacement = String.format("\\u%04x", (int) c);
                    }
            }
            if (replacement != null) {
                if (out == null) {
                    out = new StringBuilder(value.length() + 8).append(value, 0, i);
                }
                out.append(replacement);
            } else if (out != null) {
                out.append(c);
            }
        }
        return out == null ? value : out.toString();
    }

    private static boolean isLoneSurrogate(String value, int i) {
        char c = value.charAt(i);
        if (Character.isHighSurrogate(c)) {
            return i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1));
        }
        if (Character.isLowSurrogate(c)) {
            return i == 0 || !Character.isHighSurrogate(value.charAt(i - 1));
        }
        return false;
    }

    /** An iterative validator: a state machine with an explicit container stack. */
    private static final class Validator {
        private final String text;
        private int index;

        private Validator(String text) {
            this.text = text;
        }

        static boolean valid(String text) {
            Validator validator = new Validator(text);
            try {
                return validator.run();
            } catch (IndexOutOfBoundsException error) {
                return false;
            }
        }

        private void skip() {
            while (index < text.length()) {
                char c = text.charAt(index);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    index++;
                } else {
                    break;
                }
            }
        }

        private boolean run() {
            StringBuilder stack = new StringBuilder();
            skip();
            if (!value(stack)) {
                return false;
            }
            while (true) {
                skip();
                if (stack.length() == 0) {
                    return index == text.length();
                }
                char container = stack.charAt(stack.length() - 1);
                if (index >= text.length()) {
                    return false;
                }
                char c = text.charAt(index++);
                if (c == (container == '{' ? '}' : ']')) {
                    stack.setLength(stack.length() - 1);
                    continue;
                }
                if (c != ',') {
                    return false;
                }
                skip();
                if (container == '{' && !memberName()) {
                    return false;
                }
                if (!value(stack)) {
                    return false;
                }
            }
        }

        private boolean memberName() {
            if (index >= text.length() || text.charAt(index) != '"' || !string()) {
                return false;
            }
            skip();
            if (index >= text.length() || text.charAt(index) != ':') {
                return false;
            }
            index++;
            skip();
            return true;
        }

        /** Reads one value; an opened container is pushed and its first member read. */
        private boolean value(StringBuilder stack) {
            while (true) {
                if (index >= text.length()) {
                    return false;
                }
                char c = text.charAt(index);
                if (c == '{' || c == '[') {
                    index++;
                    skip();
                    char close = c == '{' ? '}' : ']';
                    if (index < text.length() && text.charAt(index) == close) {
                        index++;
                        return true;
                    }
                    stack.append(c);
                    if (c == '{' && !memberName()) {
                        return false;
                    }
                    continue;
                }
                if (c == '"') {
                    return string();
                }
                if (c == 't') {
                    return word("true");
                }
                if (c == 'f') {
                    return word("false");
                }
                if (c == 'n') {
                    return word("null");
                }
                return number();
            }
        }

        private boolean word(String word) {
            if (!text.startsWith(word, index)) {
                return false;
            }
            index += word.length();
            return true;
        }

        private boolean string() {
            index++;
            while (index < text.length()) {
                char c = text.charAt(index++);
                if (c == '"') {
                    return true;
                }
                if (c < 0x20) {
                    return false;
                }
                if (c == '\\') {
                    if (index >= text.length()) {
                        return false;
                    }
                    char escape = text.charAt(index++);
                    if (escape == 'u') {
                        if (hex4(text, index) < 0) {
                            return false;
                        }
                        index += 4;
                    } else if ("\"\\/bfnrt".indexOf(escape) < 0) {
                        return false;
                    }
                }
            }
            return false;
        }

        private boolean number() {
            int start = index;
            if (index < text.length() && text.charAt(index) == '-') {
                index++;
            }
            if (index >= text.length()) {
                return false;
            }
            if (text.charAt(index) == '0') {
                index++;
            } else if (text.charAt(index) >= '1' && text.charAt(index) <= '9') {
                while (index < text.length() && isDigit(text.charAt(index))) {
                    index++;
                }
            } else {
                return false;
            }
            if (index < text.length() && text.charAt(index) == '.') {
                index++;
                int digits = index;
                while (index < text.length() && isDigit(text.charAt(index))) {
                    index++;
                }
                if (index == digits) {
                    return false;
                }
            }
            if (index < text.length() && (text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
                index++;
                if (index < text.length() && (text.charAt(index) == '+' || text.charAt(index) == '-')) {
                    index++;
                }
                int digits = index;
                while (index < text.length() && isDigit(text.charAt(index))) {
                    index++;
                }
                if (index == digits) {
                    return false;
                }
            }
            return index > start;
        }
    }
}
