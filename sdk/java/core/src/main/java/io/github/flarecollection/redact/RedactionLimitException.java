package io.github.flarecollection.redact;

/**
 * A configured limit was exceeded, so nothing was redacted (SPEC §12). Limits fail
 * closed: a partially redacted result the caller cannot detect is worse than an
 * error.
 */
public final class RedactionLimitException extends FlareRedactException {
    private static final long serialVersionUID = 1L;

    /** @param message which limit, and by how much */
    public RedactionLimitException(String message) {
        super(message);
    }
}
