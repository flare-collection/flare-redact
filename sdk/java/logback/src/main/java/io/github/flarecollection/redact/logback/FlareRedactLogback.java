package io.github.flarecollection.redact.logback;

import io.github.flarecollection.redact.Policy;
import io.github.flarecollection.redact.RedactOptions;
import java.util.Objects;

/**
 * The policy Logback components use when their configuration does not set one.
 * Call {@link #setPolicy(Policy)} once at startup, before logging is configured,
 * to share one policy with the rest of your application.
 */
public final class FlareRedactLogback {
    private static volatile Policy policy = Policy.defaults();

    private FlareRedactLogback() {
    }

    /** @return the shared policy; the defaults until {@link #setPolicy(Policy)} is called */
    public static Policy policy() {
        return policy;
    }

    /**
     * @param value the policy every Logback component without its own options uses
     */
    public static void setPolicy(Policy value) {
        policy = Objects.requireNonNull(value, "policy");
    }

    /**
     * @param wireOptions options in the JSON wire format, or null or blank for the shared policy
     * @return the policy those options describe
     */
    static Policy resolve(String wireOptions) {
        if (wireOptions == null || wireOptions.trim().isEmpty()) {
            return policy;
        }
        return Policy.compile(RedactOptions.fromJson(wireOptions));
    }
}
