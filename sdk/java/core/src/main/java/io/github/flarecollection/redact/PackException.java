package io.github.flarecollection.redact;

/**
 * A detector pack this engine cannot run exactly as the specification describes.
 * Loading fails rather than silently weakening a check: failing open is how a
 * redactor leaks.
 */
public final class PackException extends FlareRedactException {
    private static final long serialVersionUID = 1L;

    /** @param message what is wrong with the pack */
    public PackException(String message) {
        super(message);
    }
}
