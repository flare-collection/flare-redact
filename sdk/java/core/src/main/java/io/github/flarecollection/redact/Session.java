package io.github.flarecollection.redact;

/**
 * A conversation-scoped vault. One session keeps one vault, so the same value
 * maps to the same placeholder across every turn: redact the user's message on
 * the way in, restore the model's answer on the way out.
 */
public final class Session {
    private final Policy policy;
    private final VaultOptions vaultOptions;
    private volatile Vault vault;

    /**
     * @param options what to redact
     */
    public Session(RedactOptions options) {
        this(options, VaultOptions.defaults());
    }

    /**
     * @param options what to redact
     * @param vaultOptions how placeholders are minted
     */
    public Session(RedactOptions options, VaultOptions vaultOptions) {
        this.policy = Policy.compile(options);
        this.vaultOptions = vaultOptions == null ? VaultOptions.defaults() : vaultOptions;
        this.vault = policy.vault(this.vaultOptions);
    }

    /** @return the vault holding this conversation's mappings */
    public Vault vault() {
        return vault;
    }

    /**
     * @param value a message or request body
     * @return the same shape with placeholders in place of secrets
     */
    public Object redact(Object value) {
        return vault.redact(value);
    }

    /**
     * @param text a message
     * @return the message with placeholders in place of secrets
     */
    public String redactString(String text) {
        return vault.redactString(text);
    }

    /**
     * @param value the model's reply
     * @return the reply with the originals back
     */
    public Object restore(Object value) {
        return vault.restore(value);
    }

    /**
     * @param text the model's reply
     * @return the reply with the originals back
     */
    public String restoreString(String text) {
        return vault.restoreString(text);
    }

    /** @return a restorer for a streamed reply */
    public StreamRestorer stream() {
        return vault.stream();
    }

    /** @return a restorer for a streamed reply that is JSON */
    public StreamRestorer streamJson() {
        return vault.streamJson();
    }

    /** Start a fresh conversation with no carried-over mappings. */
    public void reset() {
        vault = policy.vault(vaultOptions);
    }
}
