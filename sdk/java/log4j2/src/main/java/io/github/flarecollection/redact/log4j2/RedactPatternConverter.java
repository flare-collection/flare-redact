package io.github.flarecollection.redact.log4j2;

import io.github.flarecollection.redact.FlareRedactException;
import io.github.flarecollection.redact.Policy;
import java.util.List;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.core.pattern.ConverterKeys;
import org.apache.logging.log4j.core.pattern.LogEventPatternConverter;
import org.apache.logging.log4j.core.pattern.PatternConverter;
import org.apache.logging.log4j.core.pattern.PatternFormatter;
import org.apache.logging.log4j.core.pattern.PatternParser;

/**
 * {@code %redact{pattern}}: renders the nested pattern, then redacts it.
 *
 * <pre>{@code
 * <PatternLayout pattern="%d %-5level %logger - %redact{%msg%n%throwable}"/>
 * <PatternLayout pattern="%redact{%msg}{{&quot;mode&quot;:&quot;label&quot;}}%n"/>
 * }</pre>
 *
 * The optional second argument sets the policy for this converter in the JSON
 * wire format; without it the shared policy of {@link FlareRedactLog4j} is used.
 * When a limit is exceeded a fixed notice is written instead of the text:
 * partially redacted output looks clean and is not.
 */
@Plugin(name = "RedactPatternConverter", category = PatternConverter.CATEGORY)
@ConverterKeys({"redact"})
public final class RedactPatternConverter extends LogEventPatternConverter {
    private final List<PatternFormatter> formatters;
    private final Policy policy;

    private RedactPatternConverter(List<PatternFormatter> formatters, Policy policy) {
        super("redact", "redact");
        this.formatters = formatters;
        this.policy = policy;
    }

    /**
     * @param config the current configuration
     * @param options the nested pattern, then optional wire options
     * @return the converter, or null (with an error logged) for bad options
     */
    public static RedactPatternConverter newInstance(Configuration config, String[] options) {
        if (options == null || options.length < 1 || options[0] == null) {
            LOGGER.error("%redact needs a nested pattern, as in %redact{%msg}");
            return null;
        }
        PatternParser parser = PatternLayout.createPatternParser(config);
        List<PatternFormatter> formatters = parser.parse(options[0]);
        try {
            return new RedactPatternConverter(formatters,
                FlareRedactLog4j.resolve(options.length > 1 ? options[1] : null));
        } catch (RuntimeException error) {
            LOGGER.error("invalid flare-redact options: {}", error.getMessage());
            return null;
        }
    }

    @Override
    public void format(LogEvent event, StringBuilder toAppendTo) {
        StringBuilder rendered = new StringBuilder();
        for (PatternFormatter formatter : formatters) {
            formatter.format(event, rendered);
        }
        try {
            toAppendTo.append(policy.redactString(rendered.toString()));
        } catch (FlareRedactException error) {
            toAppendTo.append(FlareRedactLog4j.WITHHELD);
        }
    }

    @Override
    public boolean handlesThrowable() {
        for (PatternFormatter formatter : formatters) {
            if (formatter.handlesThrowable()) {
                return true;
            }
        }
        return false;
    }
}
