package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * One compiled set of options, reusable everywhere and safe to share between
 * threads. Building it resolves the detector list, the replacement and the key
 * and allow tests once, so your logs, your HTTP layer and your prompts agree on
 * what "sensitive" means.
 *
 * <p>Two decisions are worth knowing about. Overlap resolution is maximum-weight
 * interval scheduling rather than first-match, so a value two detectors match is
 * masked the same way whatever else is on the line. And limits fail closed: an
 * oversized input throws {@link RedactionLimitException} instead of returning
 * partially redacted text, because a caller cannot tell partially redacted output
 * from clean output.
 *
 * <p>Structured values are the shapes a JSON library produces: {@link Map},
 * {@link Collection}, arrays, strings and scalars. Map keys are never rewritten;
 * a string stored under a sensitive key is replaced whole. Anything else (a
 * number, a boolean, your own class) is returned unchanged: serialise a POJO to
 * JSON and use {@link #redactJson(String)}.
 */
public final class Policy {
    /** How far the learned model may move a base confidence score, up or down. */
    private static final double REFINE_STRENGTH = 0.4;

    /** Nesting deeper than this is refused rather than risking the stack. */
    static final int MAX_DEPTH = 1000;

    private final RedactOptions options;
    private final Pack pack;
    private final List<Detector> detectors;
    private final Set<String> allowed;
    private final Predicate<String> allowPredicate;
    private final Predicate<String> matchKey;
    private final BiFunction<String, Detector, String> replace;

    private Policy(RedactOptions options) {
        this.options = options;
        this.pack = options.pack != null ? options.pack : Pack.core();
        this.detectors = Collections.unmodifiableList(resolveDetectors(pack, options));
        this.allowed = new HashSet<>(options.allow);
        this.allowPredicate = options.allowPredicate;
        this.matchKey = keyMatcher(options);
        this.replace = replacer(options);
    }

    /**
     * @param options what to redact and how
     * @return the compiled policy
     * @throws FlareRedactException when a keyed mode has no transform secret
     */
    public static Policy compile(RedactOptions options) {
        return new Policy(options == null ? RedactOptions.defaults() : options);
    }

    /** @return a policy with the default options */
    public static Policy defaults() {
        return compile(RedactOptions.defaults());
    }

    /** @return the options this policy was compiled from */
    public RedactOptions options() {
        return options;
    }

    /** @return the detector pack in use */
    public Pack pack() {
        return pack;
    }

    /** @return the resolved detectors, in evaluation order */
    public List<Detector> detectors() {
        return detectors;
    }

    private static List<Detector> resolveDetectors(Pack pack, RedactOptions options) {
        List<Detector> chosen = new ArrayList<>();
        for (Detector detector : pack.detectors()) {
            if (!options.only.isEmpty()) {
                if (matchesAny(detector, options.only)) {
                    chosen.add(detector);
                }
                continue;
            }
            if ((detector.defaultOn || matchesAny(detector, options.enable)) && !matchesAny(detector, options.disable)) {
                chosen.add(detector);
            }
        }
        Detector terms = TermsMatcher.detector(options.terms, options.termsCaseSensitive);
        if (terms != null) {
            chosen.add(0, terms);
        }
        return chosen;
    }

    private static boolean matchesAny(Detector detector, List<String> selectors) {
        for (String selector : selectors) {
            if (detector.matchesSelector(selector)) {
                return true;
            }
        }
        return false;
    }

    private static Predicate<String> keyMatcher(RedactOptions options) {
        if (!options.redactKeys) {
            return key -> false;
        }
        if (options.keyNames != null) {
            Set<String> names = new HashSet<>();
            for (String name : options.keyNames) {
                names.add(Keywords.normalizeKeyName(name));
            }
            return key -> names.contains(Keywords.normalizeKeyName(key));
        }
        return Keywords::isSensitiveKeyName;
    }

    private static BiFunction<String, Detector, String> replacer(RedactOptions options) {
        if (options.maskFunction != null) {
            return options.maskFunction;
        }
        if (options.mask != null) {
            String mask = options.mask;
            return (value, detector) -> mask;
        }
        String secret = options.transformSecret;
        switch (options.mode) {
            case LABEL:
                return (value, detector) -> "[REDACTED:" + detector.id + "]";
            case HASH:
                Transforms.requireSecret(secret);
                return (value, detector) -> detector.id + "_" + Transforms.hmacFingerprint(secret, value, 16);
            case PSEUDONYM:
                Transforms.requireSecret(secret);
                return (value, detector) -> Transforms.pseudonymize(value, secret);
            case SURROGATE:
                Transforms.requireSecret(secret);
                return (value, detector) -> Transforms.surrogate(value, detector.id, secret);
            case MASK:
            default:
                return (value, detector) -> detector.mask.apply(value);
        }
    }

    boolean allows(String value) {
        return allowed.contains(value) || (allowPredicate != null && allowPredicate.test(value));
    }

    boolean isSensitiveKey(String key) {
        return matchKey.test(key);
    }

    String replacement(String value, Detector detector) {
        return replace.apply(value, detector);
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    /** One accepted match: UTF-16 offsets into the original string. */
    static final class Hit {
        final Detector detector;
        final int start;
        final int end;
        final String value;
        final double confidence;
        final double weight;

        Hit(Detector detector, int start, int end, String value, double confidence) {
            this.detector = detector;
            this.start = start;
            this.end = end;
            this.value = value;
            this.confidence = confidence;
            this.weight = detector.risk.weight() + 10.0 * detector.priority + confidence + (end - start) / 1_000_000.0;
        }
    }

    private static boolean isZeroWidth(char c) {
        return c == 0x200B || c == 0x200C || c == 0x200D || c == 0x2060 || c == 0xFEFF;
    }

    /**
     * The scan of SPEC §4 and §5. Invisible characters an attacker can splice
     * through a secret are stripped before matching, keeping a map from each unit
     * of the stripped text back to the original, so the replacement covers the
     * splice too.
     */
    List<Hit> scanHits(String text) {
        if (text.length() > options.maxInputLength) {
            throw new RedactionLimitException("input length " + text.length()
                + " exceeds the configured limit of " + options.maxInputLength);
        }
        String subject = text;
        int[] source = null;
        for (int i = 0; i < text.length(); i++) {
            if (isZeroWidth(text.charAt(i))) {
                StringBuilder stripped = new StringBuilder(text.length());
                int[] map = new int[text.length()];
                int n = 0;
                for (int j = 0; j < text.length(); j++) {
                    char c = text.charAt(j);
                    if (!isZeroWidth(c)) {
                        stripped.append(c);
                        map[n++] = j;
                    }
                }
                subject = stripped.toString();
                source = map;
                break;
            }
        }

        List<Hit> hits = new ArrayList<>();
        for (Detector detector : detectors) {
            try {
                scanDetector(detector, text, subject, source, hits);
            } catch (StackOverflowError error) {
                // java.util.regex recurses; an input built to exhaust the stack
                // must fail closed, not fall through as "nothing found".
                throw new RedactionLimitException("detector \"" + detector.id
                    + "\" exhausted the regular expression stack on this input");
            }
        }
        if (hits.size() < 2) {
            return hits;
        }
        return selectNonOverlapping(hits);
    }

    private void scanDetector(Detector detector, String text, String subject, int[] source, List<Hit> hits) {
        if (detector.prefilter != null && !detector.prefilter.matcher(subject).find()) {
            return;
        }
        for (int[] span : detector.spans(subject)) {
            int ns = span[0];
            int ne = span[1];
            if (ns < 0 || ne <= ns) {
                continue;
            }
            if (!detector.boundaryOk(subject, ns, ne)) {
                continue;
            }
            String normalized = subject.substring(ns, ne);
            if (detector.rejects(normalized) || !detector.validates(normalized)) {
                continue;
            }
            int start = ns;
            int end = ne;
            if (source != null) {
                start = source[ns];
                end = source[ne - 1] + 1;
            }
            String value = text.substring(start, end);
            if (allows(value) || (!value.equals(normalized) && allows(normalized))) {
                continue;
            }
            double confidence = scoreConfidence(detector, text, start, end);
            if (confidence < options.minConfidence) {
                continue;
            }
            hits.add(new Hit(detector, start, end, value, confidence));
            if (hits.size() > options.maxFindings) {
                throw new RedactionLimitException("finding count exceeds the configured limit of "
                    + options.maxFindings);
            }
        }
    }

    private double scoreConfidence(Detector detector, String text, int start, int end) {
        double score = detector.confidence;
        if (detector.contextPositive != null || detector.contextNegative != null) {
            int radius = detector.contextWindow;
            String nearby = text.substring(Math.max(0, start - radius), Math.min(text.length(), end + radius));
            if (detector.contextPositive != null && detector.contextPositive.matcher(nearby).find()) {
                score += 0.06;
            }
            if (detector.contextNegative != null && detector.contextNegative.matcher(nearby).find()) {
                score -= 0.25;
            }
        }
        ConfidenceModel model = pack.model();
        if (options.refineConfidence && detector.refine && model != null) {
            String window = text.substring(Math.max(0, start - 64), Math.min(text.length(), end + 64));
            score += (model.secretProbability(text.substring(start, end), window) - 0.5) * REFINE_STRENGTH;
        }
        return Math.max(0, Math.min(1, score));
    }

    /**
     * Keep the maximum-weight set of non-overlapping spans. First-match-wins would
     * make masking depend on detector order.
     */
    private static List<Hit> selectNonOverlapping(List<Hit> hits) {
        List<Hit> sorted = new ArrayList<>(hits);
        sorted.sort((a, b) -> a.end != b.end ? Integer.compare(a.end, b.end) : Integer.compare(a.start, b.start));
        int count = sorted.size();
        int[] previous = new int[count];
        for (int i = 0; i < count; i++) {
            int low = 0;
            int high = i - 1;
            int found = -1;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                if (sorted.get(mid).end <= sorted.get(i).start) {
                    found = mid;
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }
            previous[i] = found;
        }
        double[] best = new double[count + 1];
        for (int i = 1; i <= count; i++) {
            double include = sorted.get(i - 1).weight + best[previous[i - 1] + 1];
            best[i] = Math.max(best[i - 1], include);
        }
        List<Hit> selected = new ArrayList<>();
        for (int i = count; i > 0; ) {
            Hit hit = sorted.get(i - 1);
            double include = hit.weight + best[previous[i - 1] + 1];
            if (include > best[i - 1]) {
                selected.add(hit);
                i = previous[i - 1] + 1;
            } else {
                i--;
            }
        }
        Collections.reverse(selected);
        selected.sort((a, b) -> a.start != b.start ? Integer.compare(a.start, b.start) : Integer.compare(a.end, b.end));
        return selected;
    }

    String rewrite(String text, Function<Hit, String> replacement) {
        List<Hit> hits = scanHits(text);
        if (hits.isEmpty()) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length() + 16);
        int cursor = 0;
        for (Hit hit : hits) {
            out.append(text, cursor, hit.start);
            out.append(replacement.apply(hit));
            cursor = hit.end;
        }
        return out.append(text, cursor, text.length()).toString();
    }

    /**
     * Rewrite one string in a single pass. Replacements are never rescanned, so a
     * mask can never itself be masked.
     *
     * @param text the text
     * @return the redacted text
     * @throws RedactionLimitException when a configured limit is exceeded
     */
    public String redactString(String text) {
        if (text == null) {
            return null;
        }
        return rewrite(text, hit -> replace.apply(hit.value, hit.detector));
    }

    /**
     * List what would be redacted in one string, and why.
     *
     * @param text the text
     * @return the findings, ordered by position
     * @throws RedactionLimitException when a configured limit is exceeded
     */
    public List<Finding> scanString(String text) {
        List<Finding> out = new ArrayList<>();
        if (text != null) {
            scanStringInto(text, null, out);
        }
        return out;
    }

    private void scanStringInto(String text, String path, List<Finding> out) {
        int cursor = 0;
        int line = 1;
        int lineStart = 0;
        for (Hit hit : scanHits(text)) {
            while (cursor < hit.start) {
                if (text.charAt(cursor) == '\n') {
                    line++;
                    lineStart = cursor + 1;
                }
                cursor++;
            }
            Detector d = hit.detector;
            out.add(new Finding(d.id, d.label, d.why, d.risk, hit.confidence, hit.start, hit.end, line,
                hit.start - lineStart + 1, path, options.includeValues ? hit.value : null));
        }
    }

    // -----------------------------------------------------------------------
    // Structured values
    // -----------------------------------------------------------------------

    /**
     * Rewrite every string reachable from {@code value}, preserving its shape.
     * Maps come back as {@link LinkedHashMap} in the input's iteration order, lists
     * as {@link ArrayList}, sets as {@link LinkedHashSet}; a cycle in the input is
     * a cycle in the output.
     *
     * @param value a string, map, collection, array or scalar
     * @return the redacted copy
     */
    public Object redact(Object value) {
        return new Walker(this::redactString,
            (key, text) -> matchKey.test(key) && !allows(text)
                ? replace.apply(text, Detector.SENSITIVE_KEY)
                : redactString(text)).walk(value, 0);
    }

    /**
     * Redact a JSON document and return a JSON document: the entry point for your
     * own classes (serialise, redact, deserialise).
     *
     * @param json a JSON document
     * @return the redacted document
     * @throws IllegalArgumentException when {@code json} is not valid JSON
     */
    public String redactJson(String json) {
        return Json.stringify(redact(Json.parse(json)));
    }

    /** Rebuilds a structured value, transforming every string in it. */
    static final class Walker {
        private final Function<String, String> onString;
        private final BiFunction<String, String, String> onField;
        private final IdentityHashMap<Object, Object> seen = new IdentityHashMap<>();

        Walker(Function<String, String> onString, BiFunction<String, String, String> onField) {
            this.onString = onString;
            this.onField = onField;
        }

        Object walk(Object value, int depth) {
            if (value == null) {
                return null;
            }
            if (value instanceof String) {
                return onString.apply((String) value);
            }
            if (depth > MAX_DEPTH) {
                throw new FlareRedactException("value nests deeper than " + MAX_DEPTH + " levels");
            }
            Object cached = seen.get(value);
            if (cached != null) {
                return cached;
            }
            if (value instanceof Map) {
                Map<Object, Object> out = new LinkedHashMap<>();
                seen.put(value, out);
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                    Object key = entry.getKey();
                    Object item = entry.getValue();
                    if (key instanceof String && item instanceof String && onField != null) {
                        out.put(key, onField.apply((String) key, (String) item));
                    } else {
                        out.put(key, walk(item, depth + 1));
                    }
                }
                return out;
            }
            if (value instanceof Collection) {
                Collection<Object> out = value instanceof Set ? new LinkedHashSet<>() : new ArrayList<>();
                seen.put(value, out);
                for (Object item : (Collection<?>) value) {
                    out.add(walk(item, depth + 1));
                }
                return out;
            }
            if (value instanceof Object[]) {
                Object[] in = (Object[]) value;
                Object[] out = in instanceof String[] ? new String[in.length] : new Object[in.length];
                seen.put(value, out);
                for (int i = 0; i < in.length; i++) {
                    out[i] = walk(in[i], depth + 1);
                }
                return out;
            }
            return value;
        }
    }

    /**
     * List what would be redacted anywhere in {@code value}, with paths such as
     * {@code user.email} or {@code items[2]}.
     *
     * @param value a string, map, collection, array or scalar
     * @return the findings
     */
    public List<Finding> scan(Object value) {
        List<Finding> out = new ArrayList<>();
        scanValue(value, "", 0, out, Collections.newSetFromMap(new IdentityHashMap<>()));
        return out;
    }

    private void scanValue(Object value, String path, int depth, List<Finding> out, Set<Object> seen) {
        if (value == null) {
            return;
        }
        if (value instanceof String) {
            scanStringInto((String) value, path.isEmpty() ? null : path, out);
            return;
        }
        if (depth > MAX_DEPTH) {
            throw new FlareRedactException("value nests deeper than " + MAX_DEPTH + " levels");
        }
        if (value instanceof Map) {
            if (!seen.add(value)) {
                return;
            }
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                Object key = entry.getKey();
                Object item = entry.getValue();
                String name = String.valueOf(key);
                String child = path.isEmpty() ? name : path + "." + name;
                if (key instanceof String && item instanceof String && matchKey.test((String) key)
                        && !allows((String) item)) {
                    out.add(new Finding(Detector.SENSITIVE_KEY.id, Detector.SENSITIVE_KEY.label,
                        "Value stored under a sensitive field name (\"" + key + "\").", Risk.CRITICAL, 0.98,
                        -1, -1, -1, -1, child, options.includeValues ? (String) item : null));
                } else {
                    scanValue(item, child, depth + 1, out, seen);
                }
            }
            return;
        }
        if (value instanceof Collection) {
            if (!seen.add(value)) {
                return;
            }
            int index = 0;
            for (Object item : (Collection<?>) value) {
                scanValue(item, path + "[" + index++ + "]", depth + 1, out, seen);
            }
            return;
        }
        if (value instanceof Object[]) {
            if (!seen.add(value)) {
                return;
            }
            Object[] items = (Object[]) value;
            for (int i = 0; i < items.length; i++) {
                scanValue(items[i], path + "[" + i + "]", depth + 1, out, seen);
            }
        }
    }

    /**
     * @param value any supported value
     * @return whether nothing in it would be redacted
     */
    public boolean isClean(Object value) {
        return scan(value).isEmpty();
    }

    /**
     * Count findings by detector and by risk. The result holds no matched values
     * and is safe to log.
     *
     * @param value any supported value
     * @return the counts
     */
    public Summary summarize(Object value) {
        List<Finding> findings = scan(value);
        Map<String, Integer> byDetector = new LinkedHashMap<>();
        Map<String, Integer> byRisk = new LinkedHashMap<>();
        for (Finding finding : findings) {
            byDetector.merge(finding.detector(), 1, Integer::sum);
            byRisk.merge(finding.risk().wireName(), 1, Integer::sum);
        }
        return new Summary(findings.size(), byDetector, byRisk);
    }

    /** @return a new reversible redactor with opaque placeholders, sharing this policy */
    public Vault vault() {
        return new Vault(this, VaultOptions.defaults());
    }

    /**
     * @param vaultOptions how placeholders are minted
     * @return a new reversible redactor sharing this policy
     */
    public Vault vault(VaultOptions vaultOptions) {
        return new Vault(this, vaultOptions);
    }
}
