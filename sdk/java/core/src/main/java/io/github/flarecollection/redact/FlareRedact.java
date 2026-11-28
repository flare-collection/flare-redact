package io.github.flarecollection.redact;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One-line entry points. Each call with options compiles a {@link Policy} and
 * throws it away, which is fine for a script and wasteful in a request path:
 * compile once with {@link Policy#compile(RedactOptions)} and reuse it.
 *
 * <pre>{@code
 * String safe = FlareRedact.redactString("key sk-proj-... for ada@example.com");
 * Policy policy = Policy.compile(RedactOptions.builder().mode(Mode.LABEL).build());
 * }</pre>
 */
public final class FlareRedact {
    private FlareRedact() {
    }

    /** The engine version. */
    public static final String VERSION = "1.13.0";

    private static final class Defaults {
        static final Policy POLICY = Policy.defaults();
    }

    /** @return the shared policy with default options */
    public static Policy defaultPolicy() {
        return Defaults.POLICY;
    }

    /**
     * @param text the text
     * @return the text with secrets and personal data masked
     */
    public static String redactString(String text) {
        return Defaults.POLICY.redactString(text);
    }

    /**
     * @param text the text
     * @param options what to redact and how
     * @return the redacted text
     */
    public static String redactString(String text, RedactOptions options) {
        return Policy.compile(options).redactString(text);
    }

    /**
     * @param value a string, map, collection, array or scalar
     * @return the redacted copy
     */
    public static Object redact(Object value) {
        return Defaults.POLICY.redact(value);
    }

    /**
     * @param value a string, map, collection, array or scalar
     * @param options what to redact and how
     * @return the redacted copy
     */
    public static Object redact(Object value, RedactOptions options) {
        return Policy.compile(options).redact(value);
    }

    /**
     * @param value any supported value
     * @return what would be redacted, and why
     */
    public static List<Finding> scan(Object value) {
        return Defaults.POLICY.scan(value);
    }

    /**
     * @param value any supported value
     * @param options what to look for
     * @return what would be redacted, and why
     */
    public static List<Finding> scan(Object value, RedactOptions options) {
        return Policy.compile(options).scan(value);
    }

    /**
     * @param value any supported value
     * @return whether nothing in it would be redacted
     */
    public static boolean isClean(Object value) {
        return Defaults.POLICY.isClean(value);
    }

    /**
     * @param value any supported value
     * @return finding counts by detector and risk, safe to log
     */
    public static Summary summarize(Object value) {
        return Defaults.POLICY.summarize(value);
    }

    /**
     * Put originals back into any value, given placeholder to original pairs.
     *
     * @param value a string, map, collection, array or scalar
     * @param entries placeholder to original
     * @return the restored copy
     */
    public static Object restore(Object value, Map<String, String> entries) {
        List<Map.Entry<String, String>> list = new ArrayList<>();
        for (Map.Entry<String, String> entry : entries.entrySet()) {
            list.add(new AbstractMap.SimpleImmutableEntry<>(entry.getKey(), entry.getValue()));
        }
        return new Policy.Walker(Restorers.jsonAware(list), null).walk(value, 0);
    }
}
