package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Predicate;

/**
 * Everything that shapes a redaction. {@code RedactOptions.defaults()} is a working
 * configuration: the default detectors, mask mode and key redaction on.
 *
 * <p>Options are immutable; build them with {@link #builder()}, or read the JSON
 * wire format (the JavaScript library's camelCase option names) with
 * {@link #fromWire(Map)} or {@link #fromJson(String)}, so one document configures
 * every engine.
 */
public final class RedactOptions {
    /** Default cap on the UTF-16 length of one scanned string: 16 MiB. */
    public static final int DEFAULT_MAX_INPUT_LENGTH = 16 * 1024 * 1024;
    /** Default cap on findings per scanned string. */
    public static final int DEFAULT_MAX_FINDINGS = 50_000;

    private static final Set<String> WIRE_NAMES = new HashSet<>(Arrays.asList(
        "only", "enable", "disable", "mode", "mask", "transformSecret", "redactKeys", "allow", "terms",
        "termsCaseSensitive", "minConfidence", "refineConfidence", "includeValues", "limits"));

    final List<String> only;
    final List<String> enable;
    final List<String> disable;
    final Mode mode;
    final String mask;
    final BiFunction<String, Detector, String> maskFunction;
    final String transformSecret;
    final boolean redactKeys;
    final List<String> keyNames;
    final List<String> allow;
    final Predicate<String> allowPredicate;
    final List<Term> terms;
    final boolean termsCaseSensitive;
    final double minConfidence;
    final boolean refineConfidence;
    final boolean includeValues;
    final int maxInputLength;
    final int maxFindings;
    final Pack pack;

    private RedactOptions(Builder b) {
        this.only = Collections.unmodifiableList(new ArrayList<>(b.only));
        this.enable = Collections.unmodifiableList(new ArrayList<>(b.enable));
        this.disable = Collections.unmodifiableList(new ArrayList<>(b.disable));
        this.mode = b.mode;
        this.mask = b.mask;
        this.maskFunction = b.maskFunction;
        this.transformSecret = b.transformSecret;
        this.redactKeys = b.redactKeys;
        this.keyNames = b.keyNames == null ? null : Collections.unmodifiableList(new ArrayList<>(b.keyNames));
        this.allow = Collections.unmodifiableList(new ArrayList<>(b.allow));
        this.allowPredicate = b.allowPredicate;
        this.terms = Collections.unmodifiableList(new ArrayList<>(b.terms));
        this.termsCaseSensitive = b.termsCaseSensitive;
        this.minConfidence = b.minConfidence;
        this.refineConfidence = b.refineConfidence;
        this.includeValues = b.includeValues;
        this.maxInputLength = b.maxInputLength > 0 ? b.maxInputLength : DEFAULT_MAX_INPUT_LENGTH;
        this.maxFindings = b.maxFindings > 0 ? b.maxFindings : DEFAULT_MAX_FINDINGS;
        this.pack = b.pack;
    }

    /** @return the default options */
    public static RedactOptions defaults() {
        return new Builder().build();
    }

    /** @return a builder starting from the defaults */
    public static Builder builder() {
        return new Builder();
    }

    /** @return a builder holding these options, to derive a variant */
    public Builder toBuilder() {
        Builder b = new Builder();
        b.only.addAll(only);
        b.enable.addAll(enable);
        b.disable.addAll(disable);
        b.mode = mode;
        b.mask = mask;
        b.maskFunction = maskFunction;
        b.transformSecret = transformSecret;
        b.redactKeys = redactKeys;
        b.keyNames = keyNames == null ? null : new ArrayList<>(keyNames);
        b.allow.addAll(allow);
        b.allowPredicate = allowPredicate;
        b.terms.addAll(terms);
        b.termsCaseSensitive = termsCaseSensitive;
        b.minConfidence = minConfidence;
        b.refineConfidence = refineConfidence;
        b.includeValues = includeValues;
        b.maxInputLength = maxInputLength == DEFAULT_MAX_INPUT_LENGTH ? 0 : maxInputLength;
        b.maxFindings = maxFindings == DEFAULT_MAX_FINDINGS ? 0 : maxFindings;
        b.pack = pack;
        return b;
    }

    /** @return the replacement mode */
    public Mode mode() {
        return mode;
    }

    /** @return whether findings carry the raw matched value */
    public boolean includeValues() {
        return includeValues;
    }

    /** @return the UTF-16 length limit of one scanned string */
    public int maxInputLength() {
        return maxInputLength;
    }

    /** @return the finding limit per scanned string */
    public int maxFindings() {
        return maxFindings;
    }

    /**
     * Read options from a JSON wire document.
     *
     * @param json a JSON object using the wire option names
     * @return the options
     * @throws IllegalArgumentException for malformed JSON, an unknown option or a wrongly typed value
     */
    public static RedactOptions fromJson(String json) {
        Object parsed = Json.parse(json);
        if (!(parsed instanceof Map)) {
            throw new IllegalArgumentException("options must be a JSON object");
        }
        return fromWire(cast(parsed));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Object value) {
        return (Map<String, Object>) value;
    }

    /**
     * Read options from the JSON wire representation, as parsed by {@link Json#parse}.
     *
     * @param payload the wire options; null means the defaults
     * @return the options
     * @throws IllegalArgumentException for an unknown option or a wrongly typed value
     */
    public static RedactOptions fromWire(Map<String, ?> payload) {
        Builder b = new Builder();
        if (payload == null) {
            return b.build();
        }
        for (String key : payload.keySet()) {
            if (!WIRE_NAMES.contains(key)) {
                throw new IllegalArgumentException("unknown option \"" + key + "\"");
            }
        }
        if (payload.containsKey("only")) {
            b.only(strings(payload.get("only"), "only"));
        }
        if (payload.containsKey("enable")) {
            b.enable(strings(payload.get("enable"), "enable"));
        }
        if (payload.containsKey("disable")) {
            b.disable(strings(payload.get("disable"), "disable"));
        }
        if (payload.containsKey("allow")) {
            b.allow(strings(payload.get("allow"), "allow"));
        }
        if (payload.get("mode") instanceof String) {
            b.mode(Mode.fromWire((String) payload.get("mode")));
        }
        if (payload.get("mask") instanceof String) {
            b.mask((String) payload.get("mask"));
        }
        if (payload.get("transformSecret") instanceof String) {
            b.transformSecret((String) payload.get("transformSecret"));
        }
        if (payload.containsKey("redactKeys")) {
            Object value = payload.get("redactKeys");
            if (value instanceof Boolean) {
                b.redactKeys((Boolean) value);
            } else {
                b.keyNames(strings(value, "redactKeys"));
            }
        }
        if (payload.containsKey("terms")) {
            b.terms(wireTerms(payload.get("terms")));
        }
        if (payload.get("termsCaseSensitive") instanceof Boolean) {
            b.termsCaseSensitive((Boolean) payload.get("termsCaseSensitive"));
        }
        if (payload.get("minConfidence") instanceof Number) {
            b.minConfidence(((Number) payload.get("minConfidence")).doubleValue());
        }
        if (payload.get("refineConfidence") instanceof Boolean) {
            b.refineConfidence((Boolean) payload.get("refineConfidence"));
        }
        if (payload.get("includeValues") instanceof Boolean) {
            b.includeValues((Boolean) payload.get("includeValues"));
        }
        if (payload.get("limits") instanceof Map) {
            Map<?, ?> limits = (Map<?, ?>) payload.get("limits");
            if (limits.get("maxInputLength") instanceof Number) {
                b.maxInputLength(((Number) limits.get("maxInputLength")).intValue());
            }
            if (limits.get("maxFindings") instanceof Number) {
                b.maxFindings(((Number) limits.get("maxFindings")).intValue());
            }
        }
        return b.build();
    }

    private static List<String> strings(Object value, String field) {
        if (!(value instanceof List)) {
            throw new IllegalArgumentException("\"" + field + "\" must be an array of strings");
        }
        List<String> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof String)) {
                throw new IllegalArgumentException("\"" + field + "\" must be an array of strings");
            }
            out.add((String) item);
        }
        return out;
    }

    private static List<Term> wireTerms(Object value) {
        List<Term> out = new ArrayList<>();
        if (value instanceof List) {
            for (Object item : (List<?>) value) {
                if (item instanceof String) {
                    out.add(Term.of((String) item));
                } else if (item instanceof Map) {
                    Map<?, ?> entry = (Map<?, ?>) item;
                    String term = entry.get("term") instanceof String ? (String) entry.get("term") : "";
                    String replace = entry.get("replace") instanceof String ? (String) entry.get("replace") : null;
                    out.add(Term.of(term, replace));
                } else {
                    throw new IllegalArgumentException("\"terms\" entries must be strings or objects");
                }
            }
            return out;
        }
        if (value instanceof Map) {
            // A {term: replacement} object, in document order.
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                String replace = entry.getValue() instanceof String ? (String) entry.getValue() : null;
                out.add(Term.of(String.valueOf(entry.getKey()), replace));
            }
            return out;
        }
        throw new IllegalArgumentException("\"terms\" must be an array or an object");
    }

    /**
     * The wire form of these options, omitting defaults. The transform secret, the
     * mask function, the allow predicate and a custom pack are not included: the
     * secret stays where it was configured, and code cannot travel as JSON.
     *
     * @return a JSON-ready map
     */
    public Map<String, Object> toWire() {
        Map<String, Object> wire = new LinkedHashMap<>();
        if (!only.isEmpty()) {
            wire.put("only", new ArrayList<>(only));
        }
        if (!enable.isEmpty()) {
            wire.put("enable", new ArrayList<>(enable));
        }
        if (!disable.isEmpty()) {
            wire.put("disable", new ArrayList<>(disable));
        }
        if (!allow.isEmpty()) {
            wire.put("allow", new ArrayList<>(allow));
        }
        if (mode != Mode.MASK) {
            wire.put("mode", mode.wireName());
        }
        if (mask != null) {
            wire.put("mask", mask);
        }
        if (!redactKeys) {
            wire.put("redactKeys", Boolean.FALSE);
        } else if (keyNames != null) {
            wire.put("redactKeys", new ArrayList<>(keyNames));
        }
        if (!terms.isEmpty()) {
            List<Object> list = new ArrayList<>();
            for (Term term : terms) {
                if (term.replace() == null) {
                    list.add(term.term());
                } else {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("term", term.term());
                    entry.put("replace", term.replace());
                    list.add(entry);
                }
            }
            wire.put("terms", list);
        }
        if (termsCaseSensitive) {
            wire.put("termsCaseSensitive", Boolean.TRUE);
        }
        if (minConfidence > 0) {
            wire.put("minConfidence", minConfidence);
        }
        if (refineConfidence) {
            wire.put("refineConfidence", Boolean.TRUE);
        }
        if (includeValues) {
            wire.put("includeValues", Boolean.TRUE);
        }
        Map<String, Object> limits = new LinkedHashMap<>();
        if (maxInputLength != DEFAULT_MAX_INPUT_LENGTH) {
            limits.put("maxInputLength", (long) maxInputLength);
        }
        if (maxFindings != DEFAULT_MAX_FINDINGS) {
            limits.put("maxFindings", (long) maxFindings);
        }
        if (!limits.isEmpty()) {
            wire.put("limits", limits);
        }
        return wire;
    }

    /** @return {@link #toWire()} as JSON text */
    public String toJson() {
        return Json.stringify(toWire());
    }

    /** Builds {@link RedactOptions}. Every setter returns the builder. */
    public static final class Builder {
        private final List<String> only = new ArrayList<>();
        private final List<String> enable = new ArrayList<>();
        private final List<String> disable = new ArrayList<>();
        private Mode mode = Mode.MASK;
        private String mask;
        private BiFunction<String, Detector, String> maskFunction;
        private String transformSecret = "";
        private boolean redactKeys = true;
        private List<String> keyNames;
        private final List<String> allow = new ArrayList<>();
        private Predicate<String> allowPredicate;
        private final List<Term> terms = new ArrayList<>();
        private boolean termsCaseSensitive;
        private double minConfidence;
        private boolean refineConfidence;
        private boolean includeValues;
        private int maxInputLength;
        private int maxFindings;
        private Pack pack;

        private Builder() {
        }

        /** Use exactly these detector ids or tags, ignoring defaults. */
        public Builder only(String... selectors) {
            return only(Arrays.asList(selectors));
        }

        /** Use exactly these detector ids or tags, ignoring defaults. */
        public Builder only(List<String> selectors) {
            only.clear();
            only.addAll(selectors);
            return this;
        }

        /** Turn on non-default detectors by id or tag. */
        public Builder enable(String... selectors) {
            return enable(Arrays.asList(selectors));
        }

        /** Turn on non-default detectors by id or tag. */
        public Builder enable(List<String> selectors) {
            enable.clear();
            enable.addAll(selectors);
            return this;
        }

        /** Turn off detectors by id or tag. */
        public Builder disable(String... selectors) {
            return disable(Arrays.asList(selectors));
        }

        /** Turn off detectors by id or tag. */
        public Builder disable(List<String> selectors) {
            disable.clear();
            disable.addAll(selectors);
            return this;
        }

        /** Select the replacement strategy. */
        public Builder mode(Mode value) {
            mode = value == null ? Mode.MASK : value;
            return this;
        }

        /** A fixed replacement string; wins over the mode. */
        public Builder mask(String value) {
            mask = value;
            return this;
        }

        /** Replace a matched value with your own function; wins over the mask and the mode. */
        public Builder maskFunction(BiFunction<String, Detector, String> value) {
            maskFunction = value;
            return this;
        }

        /** The key for hash, pseudonym and surrogate modes. Never hard-code it. */
        public Builder transformSecret(String value) {
            transformSecret = value == null ? "" : value;
            return this;
        }

        /** Turn the "sensitive by field name" rule on (the default) or off. */
        public Builder redactKeys(boolean value) {
            redactKeys = value;
            keyNames = null;
            return this;
        }

        /** Replace the built-in sensitive-name test with an exact list of field names. */
        public Builder keyNames(String... names) {
            return keyNames(Arrays.asList(names));
        }

        /**
         * Replace the built-in sensitive-name test with an exact list of field names,
         * compared after the key normalisation of SPEC §6. An empty list matches no key.
         */
        public Builder keyNames(List<String> names) {
            redactKeys = true;
            keyNames = new ArrayList<>(names);
            return this;
        }

        /** Values that are never redacted. */
        public Builder allow(String... values) {
            return allow(Arrays.asList(values));
        }

        /** Values that are never redacted. */
        public Builder allow(List<String> values) {
            allow.clear();
            allow.addAll(values);
            return this;
        }

        /** An additional test for values that are never redacted. */
        public Builder allowPredicate(Predicate<String> value) {
            allowPredicate = value;
            return this;
        }

        /** Your own words and phrases to always catch, masked as {@code ***}. */
        public Builder terms(String... words) {
            List<Term> list = new ArrayList<>();
            for (String word : words) {
                list.add(Term.of(word));
            }
            return terms(list);
        }

        /** Your own words and phrases to always catch, each with an optional replacement. */
        public Builder terms(List<Term> value) {
            terms.clear();
            terms.addAll(value);
            return this;
        }

        /** Match terms exactly as written (default: case-insensitive). */
        public Builder termsCaseSensitive(boolean value) {
            termsCaseSensitive = value;
            return this;
        }

        /** Drop findings scored below this confidence. */
        public Builder minConfidence(double value) {
            minConfidence = value;
            return this;
        }

        /** Let the learned classifier adjust the confidence of generic detectors. */
        public Builder refineConfidence(boolean value) {
            refineConfidence = value;
            return this;
        }

        /** Put raw matched values in findings. Unsafe for logs and reports. */
        public Builder includeValues(boolean value) {
            includeValues = value;
            return this;
        }

        /** Cap the UTF-16 length of one scanned string; 0 restores the default. */
        public Builder maxInputLength(int value) {
            maxInputLength = value;
            return this;
        }

        /** Cap findings per scanned string; 0 restores the default. */
        public Builder maxFindings(int value) {
            maxFindings = value;
            return this;
        }

        /** Use another detector pack instead of the bundled one. */
        public Builder pack(Pack value) {
            pack = value;
            return this;
        }

        /** @return the options */
        public RedactOptions build() {
            return new RedactOptions(this);
        }
    }
}
