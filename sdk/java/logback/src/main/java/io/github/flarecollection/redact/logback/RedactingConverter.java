package io.github.flarecollection.redact.logback;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.pattern.CompositeConverter;
import io.github.flarecollection.redact.FlareRedactException;
import io.github.flarecollection.redact.Policy;
import java.util.List;

/**
 * {@code %redact(...)}: redacts whatever the wrapped pattern renders.
 *
 * <pre>{@code
 * <conversionRule conversionWord="redact"
 *     converterClass="io.github.flarecollection.redact.logback.RedactingConverter"/>
 * <pattern>%d %-5level %logger - %redact(%msg%n%ex)</pattern>
 * }</pre>
 *
 * An option sets the policy for this converter in the JSON wire format, for
 * example {@code %redact(%msg){'{"mode":"label"}'}}; without one the shared
 * policy of {@link FlareRedactLogback} is used.
 *
 * <p>When a limit is exceeded the converter writes a fixed notice instead of the
 * text: partially redacted output looks clean and is not.
 */
public class RedactingConverter extends CompositeConverter<ILoggingEvent> {
    static final String WITHHELD = "[flare-redact: log text withheld, redaction limit exceeded]";

    private Policy policy;

    @Override
    public void start() {
        List<String> options = getOptionList();
        try {
            policy = FlareRedactLogback.resolve(options == null || options.isEmpty() ? null : options.get(0));
        } catch (RuntimeException error) {
            addError("invalid flare-redact options: " + error.getMessage(), error);
            policy = FlareRedactLogback.policy();
        }
        super.start();
    }

    @Override
    protected String transform(ILoggingEvent event, String in) {
        Policy active = policy != null ? policy : FlareRedactLogback.policy();
        try {
            return active.redactString(in);
        } catch (FlareRedactException error) {
            return WITHHELD;
        }
    }
}
