package io.github.flarecollection.redact;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A loaded, compiled FRS-1 detector pack.
 *
 * <p>Loading is strict on purpose. A pack that uses a construct this engine cannot
 * run exactly as the specification describes (a lookahead, a {@code \d} whose
 * meaning differs between languages, a checksum this build does not know) fails
 * with a {@link PackException}. Failing open is how a redactor leaks.
 */
public final class Pack {
    /** The FRS-1 revision this engine implements. */
    public static final String SPEC_REVISION = "FRS-1";

    private static final String CORE_RESOURCE = "detectors.json";

    private static final Map<String, String> BOUNDARY_CLASSES;

    static {
        String lower = "abcdefghijklmnopqrstuvwxyz";
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digits = "0123456789";
        Map<String, String> classes = new HashMap<>();
        classes.put("word", lower + upper + digits + "_");
        classes.put("alnum", lower + upper + digits);
        classes.put("digit", digits);
        classes.put("hex", digits + "abcdefABCDEF");
        classes.put("base64", lower + upper + digits + "+/=");
        classes.put("base64url", lower + upper + digits + "_+/=-");
        classes.put("word_dash", lower + upper + digits + "_-");
        BOUNDARY_CLASSES = Collections.unmodifiableMap(classes);
    }

    private static final String FORBIDDEN_ESCAPES = "bBdDwWsSpP123456789AZzGkK";

    private final String id;
    private final String version;
    private final String title;
    private final List<Detector> detectors;
    private final Map<String, Detector> byId;
    private final ConfidenceModel model;

    private Pack(String id, String version, String title, List<Detector> detectors, ConfidenceModel model) {
        this.id = id;
        this.version = version;
        this.title = title;
        this.detectors = Collections.unmodifiableList(detectors);
        Map<String, Detector> index = new LinkedHashMap<>();
        for (Detector detector : detectors) {
            index.put(detector.id, detector);
        }
        this.byId = Collections.unmodifiableMap(index);
        this.model = model;
    }

    /** @return the pack identifier, such as {@code flare-redact/core} */
    public String id() {
        return id;
    }

    /** @return the pack version */
    public String version() {
        return version;
    }

    /** @return the human-readable title */
    public String title() {
        return title;
    }

    /** @return the detectors, in evaluation order */
    public List<Detector> detectors() {
        return detectors;
    }

    /**
     * @param detectorId a detector id
     * @return the detector, or null
     */
    public Detector detector(String detectorId) {
        return byId.get(detectorId);
    }

    /** @return the learned confidence classifier, or null when the pack has none */
    public ConfidenceModel model() {
        return model;
    }

    private static final class Holder {
        static final Pack CORE = loadCore();

        private static Pack loadCore() {
            try (InputStream in = Pack.class.getResourceAsStream(CORE_RESOURCE)) {
                if (in == null) {
                    throw new PackException("the bundled detector pack is missing from the jar");
                }
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] chunk = new byte[16384];
                for (int n; (n = in.read(chunk)) > 0; ) {
                    buffer.write(chunk, 0, n);
                }
                return load(new String(buffer.toByteArray(), StandardCharsets.UTF_8));
            } catch (IOException error) {
                throw new PackException("cannot read the bundled detector pack: " + error.getMessage());
            }
        }
    }

    /** @return the bundled {@code flare-redact/core} pack, compiled once per class loader */
    public static Pack core() {
        return Holder.CORE;
    }

    /**
     * Compile an FRS-1 pack document.
     *
     * @param json the pack as JSON text
     * @return the compiled pack
     * @throws PackException for anything this engine cannot honour exactly
     */
    public static Pack load(String json) {
        Object parsed;
        try {
            parsed = Json.parse(json);
        } catch (IllegalArgumentException error) {
            throw new PackException("pack is not valid JSON: " + error.getMessage());
        }
        if (!(parsed instanceof Map)) {
            throw new PackException("a pack must be a JSON object");
        }
        Map<?, ?> document = (Map<?, ?>) parsed;
        if (!SPEC_REVISION.equals(document.get("spec"))) {
            throw new PackException("unsupported pack revision " + Json.stringify(document.get("spec"))
                + "; this engine implements " + SPEC_REVISION);
        }
        Object detectorList = document.get("detectors");
        if (!(detectorList instanceof List) || ((List<?>) detectorList).isEmpty()) {
            throw new PackException("a pack must declare at least one detector");
        }
        List<Detector> detectors = new ArrayList<>();
        Map<String, Boolean> seen = new HashMap<>();
        for (Object spec : (List<?>) detectorList) {
            if (!(spec instanceof Map)) {
                throw new PackException("every detector must be a JSON object");
            }
            Detector detector = compileDetector((Map<?, ?>) spec);
            if (seen.put(detector.id, Boolean.TRUE) != null) {
                throw new PackException("duplicate detector id \"" + detector.id + "\"");
            }
            detectors.add(detector);
        }
        ConfidenceModel model = null;
        if (document.get("confidenceModel") instanceof Map) {
            Map<?, ?> spec = (Map<?, ?>) document.get("confidenceModel");
            List<String> features = new ArrayList<>();
            for (Object feature : list(spec.get("features"))) {
                features.add(String.valueOf(feature));
            }
            List<?> weightList = list(spec.get("weights"));
            double[] weights = new double[weightList.size()];
            for (int i = 0; i < weights.length; i++) {
                weights[i] = number(weightList.get(i), 0);
            }
            model = new ConfidenceModel((int) number(spec.get("version"), 0), features, weights,
                number(spec.get("bias"), 0));
        }
        String id = string(document.get("id"));
        String title = document.get("title") instanceof String ? (String) document.get("title") : id;
        return new Pack(id, string(document.get("version")), title, detectors, model);
    }

    private static List<?> list(Object value) {
        return value instanceof List ? (List<?>) value : Collections.emptyList();
    }

    private static String string(Object value) {
        return value instanceof String ? (String) value : "";
    }

    private static double number(Object value, double fallback) {
        return value instanceof Number ? ((Number) value).doubleValue() : fallback;
    }

    /** Reject constructs whose meaning differs between the FRS-1 target engines. */
    static void assertPortable(String pattern, String where) {
        int index = 0;
        boolean inClass = false;
        while (index < pattern.length()) {
            char ch = pattern.charAt(index);
            if (ch == '\\') {
                if (index + 1 >= pattern.length()) {
                    throw new PackException(where + ": pattern ends with a dangling backslash");
                }
                char next = pattern.charAt(index + 1);
                if (FORBIDDEN_ESCAPES.indexOf(next) >= 0) {
                    throw new PackException(where + ": '\\" + next + "' is not portable across FRS-1 engines;"
                        + " write the character class out, or use {{ANY}} / {{L}}");
                }
                index += 2;
                continue;
            }
            if (inClass) {
                if (ch == ']') {
                    inClass = false;
                }
                index++;
                continue;
            }
            if (ch == '[') {
                index++;
                if (index < pattern.length() && pattern.charAt(index) == '^') {
                    index++;
                }
                if (index < pattern.length() && pattern.charAt(index) == ']') {
                    index++;
                }
                inClass = true;
                continue;
            }
            if (ch == '(' && index + 1 < pattern.length() && pattern.charAt(index + 1) == '?') {
                if (index + 2 >= pattern.length() || pattern.charAt(index + 2) != ':') {
                    throw new PackException(where + ": only '(...)' and '(?:...)' groups are portable across"
                        + " FRS-1 engines");
                }
                index += 3;
                continue;
            }
            if (ch == '^' || ch == '$') {
                throw new PackException(where + ": anchors are not allowed inside a detector pattern");
            }
            index++;
        }
        if (inClass) {
            throw new PackException(where + ": unterminated character class");
        }
    }

    static Pattern compile(String pattern, String flags, String where, boolean portable) {
        if (portable) {
            assertPortable(pattern, where);
        }
        try {
            return Pattern.compile(PatternTranslator.translate(pattern, flags != null && flags.contains("i")));
        } catch (IllegalArgumentException error) {
            throw new PackException(where + ": invalid pattern (" + error.getMessage() + ")");
        }
    }

    private static Detector compileDetector(Map<?, ?> spec) {
        for (String field : new String[] {"id", "label", "why", "pattern", "mask", "default", "risk", "confidence"}) {
            if (spec.get(field) == null) {
                throw new PackException("detector is missing required field \"" + field + "\"");
            }
        }
        String where = "detector \"" + spec.get("id") + "\"";
        Detector.Builder b = new Detector.Builder();
        b.id = string(spec.get("id"));
        b.label = string(spec.get("label"));
        b.why = string(spec.get("why"));
        b.risk = Risk.fromWire(string(spec.get("risk")));
        if (b.risk == null) {
            throw new PackException(where + ": risk must be one of low, medium, high, critical");
        }
        b.confidence = number(spec.get("confidence"), -1);
        if (!(b.confidence >= 0 && b.confidence <= 1)) {
            throw new PackException(where + ": confidence must be between 0 and 1");
        }
        String flags = spec.get("flags") instanceof String ? (String) spec.get("flags") : "";
        if (!flags.isEmpty() && !flags.equals("i")) {
            throw new PackException(where + ": only the 'i' flag is portable");
        }
        b.defaultOn = Boolean.TRUE.equals(spec.get("default"));
        b.priority = (int) number(spec.get("priority"), 0);
        b.refine = Boolean.TRUE.equals(spec.get("refine"));
        for (Object tag : list(spec.get("tags"))) {
            b.tags.add(String.valueOf(tag));
        }

        b.pattern = compile(string(spec.get("pattern")), flags, where, true);
        b.first = FirstSet.of(string(spec.get("pattern")), flags.equals("i"));
        if (b.pattern.matcher("").find()) {
            throw new PackException(where + ": pattern matches the empty string");
        }
        b.capture = (int) number(spec.get("capture"), 0);
        if (b.capture > b.pattern.matcher("").groupCount()) {
            throw new PackException(where + ": capture group " + b.capture + " does not exist");
        }

        if (spec.get("boundary") instanceof Map) {
            Map<?, ?> boundary = (Map<?, ?>) spec.get("boundary");
            b.before = boundaryClass(boundary.get("before"), where);
            b.after = boundaryClass(boundary.get("after"), where);
        }

        List<?> prefilter = list(spec.get("prefilter"));
        if (!prefilter.isEmpty()) {
            StringBuilder alternation = new StringBuilder();
            for (Object literal : prefilter) {
                if (alternation.length() > 0) {
                    alternation.append('|');
                }
                alternation.append(PatternTranslator.literal(String.valueOf(literal), true));
            }
            b.prefilter = Pattern.compile(alternation.toString());
        }

        for (Object reject : list(spec.get("reject"))) {
            b.reject.add(compile(String.valueOf(reject), flags, where + " reject", false));
        }
        for (Object validator : list(spec.get("validators"))) {
            if (!(validator instanceof Map)) {
                throw new PackException(where + ": every validator must be a JSON object");
            }
            b.validators.add(buildValidator((Map<?, ?>) validator, where));
        }
        if (!(spec.get("mask") instanceof Map)) {
            throw new PackException(where + ": mask must be a JSON object");
        }
        b.mask = buildMask((Map<?, ?>) spec.get("mask"), where);

        if (spec.get("context") instanceof Map) {
            Map<?, ?> context = (Map<?, ?>) spec.get("context");
            if (context.get("positive") instanceof String) {
                b.contextPositive = compile((String) context.get("positive"), "i", where + " context", false);
            }
            if (context.get("negative") instanceof String) {
                b.contextNegative = compile((String) context.get("negative"), "i", where + " context", false);
            }
            int window = (int) number(context.get("window"), 0);
            if (window > 0) {
                b.contextWindow = window;
            }
        }
        return new Detector(b);
    }

    private static String boundaryClass(Object name, String where) {
        if (name == null) {
            return null;
        }
        String members = BOUNDARY_CLASSES.get(String.valueOf(name));
        if (members == null) {
            throw new PackException(where + ": unknown boundary class \"" + name + "\"");
        }
        return members;
    }

    private static Predicate<String> buildValidator(Map<?, ?> spec, String where) {
        String name = string(spec.get("name"));
        switch (name) {
            case "normalized_match": {
                Pattern strip = spec.get("strip") instanceof String && !((String) spec.get("strip")).isEmpty()
                    ? compile((String) spec.get("strip"), "", where + " validator strip", false)
                    : null;
                Pattern target = compile(string(spec.get("pattern")), "", where + " validator", false);
                return value -> {
                    String candidate = strip == null ? value : strip.matcher(value).replaceAll("");
                    return target.matcher(candidate).matches();
                };
            }
            case "luhn": {
                int min = (int) number(spec.get("minDigits"), 2);
                int max = (int) number(spec.get("maxDigits"), 0);
                return value -> Checksums.luhn(value, min, max);
            }
            case "entropy": {
                double min = number(spec.get("min"), 0);
                return value -> Checksums.shannonEntropy(value) >= min;
            }
            default: {
                Predicate<String> named = Checksums.NAMED.get(name);
                if (named == null) {
                    throw new PackException(where + ": unknown validator \"" + name + "\"; refusing to load a pack"
                        + " whose checks this engine cannot perform");
                }
                return named;
            }
        }
    }

    private static Function<String, String> buildMask(Map<?, ?> spec, String where) {
        String type = string(spec.get("type"));
        switch (type) {
            case "fixed": {
                String text = spec.get("text") instanceof String ? (String) spec.get("text") : "***";
                return value -> text;
            }
            case "keepPrefix": {
                int n = (int) number(spec.get("n"), 0);
                return value -> value.length() <= n ? "***" : value.substring(0, n) + "***";
            }
            case "keepLast": {
                int n = (int) number(spec.get("n"), 0);
                return value -> {
                    String digits = Checksums.digitsOf(value);
                    String tail = digits.length() > n ? digits.substring(digits.length() - n) : digits;
                    int groups = digits.length() > n ? (digits.length() - n + 3) / 4 : 0;
                    StringBuilder out = new StringBuilder();
                    for (int i = 0; i < groups; i++) {
                        out.append("**** ");
                    }
                    return out.append(tail).toString().trim();
                };
            }
            case "keepThroughSeparator": {
                String separator = string(spec.get("separator"));
                int count = (int) number(spec.get("count"), 1);
                return value -> {
                    int index = -separator.length();
                    for (int n = 0; n < count; n++) {
                        index = value.indexOf(separator, index + separator.length());
                        if (index < 0) {
                            return "***";
                        }
                    }
                    return value.substring(0, index + separator.length()) + "***";
                };
            }
            case "replace": {
                String flags = spec.get("flags") instanceof String ? (String) spec.get("flags") : "";
                Pattern pattern = compile(string(spec.get("pattern")), flags, where + " mask", false);
                String replacement = string(spec.get("replacement"));
                return value -> {
                    Matcher matcher = pattern.matcher(value);
                    return matcher.matches() ? expandReplacement(replacement, matcher) : value;
                };
            }
            default:
                throw new PackException(where + ": unknown mask type \"" + type + "\"");
        }
    }

    /** Substitute {@code $1}...{@code $9} and {@code $$} in a mask replacement template. */
    private static String expandReplacement(String template, Matcher match) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < template.length(); i++) {
            char c = template.charAt(i);
            if (c == '$' && i + 1 < template.length()) {
                char next = template.charAt(i + 1);
                if (next == '$') {
                    out.append('$');
                    i++;
                    continue;
                }
                if (next >= '1' && next <= '9') {
                    int group = next - '0';
                    if (group <= match.groupCount() && match.group(group) != null) {
                        out.append(match.group(group));
                    }
                    i++;
                    continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }
}
