package io.github.flarecollection.redact;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A reversible redactor. Each secret is swapped for a stable placeholder and the
 * mapping is remembered, so you can send the redacted text to a model and put the
 * originals back into its answer. The same value always maps to the same
 * placeholder within one vault, so references survive the round trip.
 *
 * <p>A vault is thread-safe. It holds the originals in memory: keep it for one
 * conversation (see {@link Session}) and let it go.
 */
public final class Vault {
    private final Policy policy;
    private final VaultOptions vaultOptions;
    private final Map<String, String> byValue = new HashMap<>();
    private final Map<String, String> byPlaceholder = new LinkedHashMap<>();
    private final Map<String, Integer> counts = new HashMap<>();

    Vault(Policy policy, VaultOptions vaultOptions) {
        this.policy = policy;
        this.vaultOptions = vaultOptions == null ? VaultOptions.defaults() : vaultOptions;
    }

    /**
     * @param options what to redact
     * @return a vault with opaque placeholders
     */
    public static Vault create(RedactOptions options) {
        return Policy.compile(options).vault();
    }

    /**
     * @param options what to redact
     * @param vaultOptions how placeholders are minted
     * @return the vault
     */
    public static Vault create(RedactOptions options, VaultOptions vaultOptions) {
        return Policy.compile(options).vault(vaultOptions);
    }

    /** @return the policy this vault redacts with */
    public Policy policy() {
        return policy;
    }

    private String mint(String value, String detectorId) {
        String existing = byValue.get(value);
        if (existing != null) {
            return existing;
        }
        int index = counts.merge(detectorId, 1, Integer::sum);
        String placeholder = vaultOptions.placeholder.apply(detectorId, index);
        String collision = byPlaceholder.get(placeholder);
        if (collision != null && !collision.equals(value)) {
            throw new FlareRedactException("the placeholder generator produced a duplicate token for " + detectorId);
        }
        byValue.put(value, placeholder);
        byPlaceholder.put(placeholder, value);
        return placeholder;
    }

    /**
     * Replace every secret in {@code text} with a stable placeholder. A value
     * found inside a JSON document is stored decoded, so restoring it into JSON
     * escapes it exactly once and restoring it into prose gives the value.
     *
     * @param text the text
     * @return the text with placeholders
     */
    public synchronized String redactString(String text) {
        if (text == null) {
            return null;
        }
        int[] json = {-1};
        return policy.rewrite(text, hit -> {
            if (json[0] < 0) {
                json[0] = Restorers.isJsonDocument(text) ? 1 : 0;
            }
            String value = hit.value;
            if (json[0] == 1) {
                String decoded = Restorers.decodeJsonStringContent(value);
                if (decoded != null) {
                    value = decoded;
                }
            }
            return mint(value, hit.detector.id);
        });
    }

    /**
     * Replace every secret reachable from {@code value} with a stable placeholder,
     * preserving its shape (see {@link Policy#redact(Object)}). Every string and
     * number under a sensitive key gets one; a number restores as its text.
     *
     * @param value a string, map, collection, array or scalar
     * @return the redacted copy
     */
    public synchronized Object redact(Object value) {
        return new Policy.Walker(this::redactString, policy::isSensitiveKey,
            text -> policy.allows(text) ? null : mint(text, Detector.SENSITIVE_KEY.id)).walk(value, 0);
    }

    /** @return placeholder, original pairs in the order they were minted */
    public synchronized List<Map.Entry<String, String>> entries() {
        List<Map.Entry<String, String>> out = new ArrayList<>(byPlaceholder.size());
        for (Map.Entry<String, String> entry : byPlaceholder.entrySet()) {
            out.add(new AbstractMap.SimpleImmutableEntry<>(entry.getKey(), entry.getValue()));
        }
        return out;
    }

    /** @return the number of distinct values replaced so far */
    public synchronized int size() {
        return byPlaceholder.size();
    }

    /**
     * Put the originals back into {@code text}. When the text is a JSON object or
     * array, the originals go in JSON-escaped.
     *
     * @param text text that may hold placeholders
     * @return the restored text
     */
    public String restoreString(String text) {
        return Restorers.jsonAware(entries()).apply(text);
    }

    /**
     * Put the originals back into any supported value.
     *
     * @param value a string, map, collection, array or scalar
     * @return the restored copy
     */
    public Object restore(Object value) {
        return new Policy.Walker(Restorers.jsonAware(entries()), null, null).walk(value, 0);
    }

    /** @return a restorer for streamed output, safe across chunk boundaries */
    public StreamRestorer stream() {
        return new StreamRestorer(entries());
    }

    /** @return a stream restorer for output that is JSON, such as tool-call arguments */
    public StreamRestorer streamJson() {
        return new StreamRestorer(Restorers.escapeForJson(entries()));
    }
}
