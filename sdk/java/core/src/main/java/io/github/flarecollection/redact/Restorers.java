package io.github.flarecollection.redact;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Putting originals back. Every restorer here is single-pass and matches longer
 * placeholders first, so a token that is a prefix of another cannot clobber its
 * peer and restore the wrong secret.
 */
public final class Restorers {
    private Restorers() {
    }

    /**
     * A single-pass restorer for placeholder to original pairs.
     *
     * @param entries placeholder, original pairs
     * @return a function that restores every placeholder in a string
     */
    public static Function<String, String> plain(List<Map.Entry<String, String>> entries) {
        List<Map.Entry<String, String>> ordered = new ArrayList<>();
        for (Map.Entry<String, String> entry : entries) {
            if (!entry.getKey().isEmpty()) {
                ordered.add(entry);
            }
        }
        if (ordered.isEmpty()) {
            return Function.identity();
        }
        // Longest first; the sort is stable, so equal lengths keep mint order.
        ordered.sort((a, b) -> Integer.compare(b.getKey().length(), a.getKey().length()));
        Map<String, String> lookup = new HashMap<>();
        StringBuilder alternation = new StringBuilder();
        for (Map.Entry<String, String> entry : ordered) {
            lookup.put(entry.getKey(), entry.getValue());
            if (alternation.length() > 0) {
                alternation.append('|');
            }
            alternation.append(Pattern.quote(entry.getKey()));
        }
        Pattern pattern = Pattern.compile(alternation.toString());
        return text -> {
            if (text == null) {
                return null;
            }
            Matcher matcher = pattern.matcher(text);
            if (!matcher.find()) {
                return text;
            }
            StringBuilder out = new StringBuilder(text.length() + 32);
            int cursor = 0;
            do {
                out.append(text, cursor, matcher.start());
                String original = lookup.get(matcher.group());
                out.append(original != null ? original : matcher.group());
                cursor = matcher.end();
            } while (matcher.find());
            return out.append(text, cursor, text.length()).toString();
        };
    }

    /**
     * The pairs with each original escaped for the inside of a JSON string literal
     * (SPEC §11). A placeholder can only sit inside a string in valid JSON, so an
     * original spliced in this form keeps the JSON valid, and quotes, backslashes or
     * control characters in it cannot end the string and add or replace fields.
     *
     * @param entries placeholder, original pairs
     * @return placeholder, escaped original pairs
     */
    public static List<Map.Entry<String, String>> escapeForJson(List<Map.Entry<String, String>> entries) {
        List<Map.Entry<String, String>> out = new ArrayList<>(entries.size());
        for (Map.Entry<String, String> entry : entries) {
            out.add(new AbstractMap.SimpleImmutableEntry<>(entry.getKey(), Json.escape(entry.getValue())));
        }
        return out;
    }

    /**
     * {@link #plain}, except that a string which is a JSON object or array (tool
     * call arguments, JSON-mode output) gets the originals JSON-escaped, so it is
     * still valid JSON with the same structure after the restore.
     *
     * @param entries placeholder, original pairs
     * @return the restorer
     */
    public static Function<String, String> jsonAware(List<Map.Entry<String, String>> entries) {
        if (entries.isEmpty()) {
            return Function.identity();
        }
        Function<String, String> plain = plain(entries);
        AtomicReference<Function<String, String>> escaped = new AtomicReference<>();
        return text -> {
            if (text == null) {
                return null;
            }
            String restored = plain.apply(text);
            if (restored.equals(text) || !isJsonDocument(text)) {
                return restored;
            }
            Function<String, String> json = escaped.get();
            if (json == null) {
                json = plain(escapeForJson(entries));
                escaped.set(json);
            }
            return json.apply(text);
        };
    }

    /**
     * @param text any text
     * @return whether it is a complete JSON object or array
     */
    public static boolean isJsonDocument(String text) {
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                break;
            }
            i++;
        }
        if (i >= text.length() || (text.charAt(i) != '{' && text.charAt(i) != '[')) {
            return false;
        }
        return Json.isValid(text);
    }

    /**
     * {@code text} read as the content of a JSON string literal, or null when it is
     * not valid content: an unescaped quote or control character, an unknown or
     * cut-off escape, or a {@code \}{@code u} escape that leaves a lone surrogate.
     */
    static String decodeJsonStringContent(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == '"' || c < 0x20) {
                return null;
            }
            if (c != '\\') {
                out.append(c);
                i++;
                continue;
            }
            char next = i + 1 < text.length() ? text.charAt(i + 1) : 0;
            switch (next) {
                case '"':
                case '\\':
                case '/':
                    out.append(next);
                    i += 2;
                    continue;
                case 'b':
                    out.append('\b');
                    i += 2;
                    continue;
                case 'f':
                    out.append('\f');
                    i += 2;
                    continue;
                case 'n':
                    out.append('\n');
                    i += 2;
                    continue;
                case 'r':
                    out.append('\r');
                    i += 2;
                    continue;
                case 't':
                    out.append('\t');
                    i += 2;
                    continue;
                case 'u':
                    break;
                default:
                    return null;
            }
            int unit = Json.hex4(text, i + 2);
            i += 6;
            if (unit < 0 || (unit >= 0xDC00 && unit <= 0xDFFF)) {
                return null;
            }
            if (unit >= 0xD800 && unit <= 0xDBFF) {
                int low = i + 1 < text.length() && text.charAt(i) == '\\' && text.charAt(i + 1) == 'u'
                    ? Json.hex4(text, i + 2) : -1;
                if (low < 0xDC00 || low > 0xDFFF) {
                    return null;
                }
                out.append((char) unit).append((char) low);
                i += 6;
                continue;
            }
            out.append((char) unit);
        }
        return out.toString();
    }
}
