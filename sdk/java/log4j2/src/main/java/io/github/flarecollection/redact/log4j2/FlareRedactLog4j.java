package io.github.flarecollection.redact.log4j2;

import io.github.flarecollection.redact.Policy;
import io.github.flarecollection.redact.RedactOptions;
import java.util.Objects;

/**
 * The policy Log4j 2 components use when their configuration does not set one.
 * Call {@link #setPolicy(Policy)} once at startup, before Log4j is configured,
 * to share one policy with the rest of your application.
 */
public final class FlareRedactLog4j {
    private static volatile Policy policy = Policy.defaults();

    private FlareRedactLog4j() {
    }

    /** @return the shared policy; the defaults until {@link #setPolicy(Policy)} is called */
    public static Policy policy() {
        return policy;
    }

    /** @param value the policy every Log4j component without its own options uses */
    public static void setPolicy(Policy value) {
        policy = Objects.requireNonNull(value, "policy");
    }

    static Policy resolve(String wireOptions) {
        if (wireOptions == null || wireOptions.trim().isEmpty()) {
            return policy;
        }
        return Policy.compile(RedactOptions.fromJson(wireOptions));
    }

    static final String WITHHELD = "[flare-redact: log text withheld, redaction limit exceeded]";
}
