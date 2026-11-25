package io.github.flarecollection.redact;

/** Base class of every error this library raises. */
public class FlareRedactException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** @param message what went wrong */
    public FlareRedactException(String message) {
        super(message);
    }

    /**
     * @param message what went wrong
     * @param cause the underlying error
     */
    public FlareRedactException(String message, Throwable cause) {
        super(message, cause);
    }
}
