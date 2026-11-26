package io.github.flarecollection.redact.log4j2;

import io.github.flarecollection.redact.FlareRedactException;
import io.github.flarecollection.redact.Policy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.rewrite.RewritePolicy;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.MapMessage;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.util.SortedArrayStringMap;
import org.apache.logging.log4j.util.StringMap;

/**
 * A rewrite policy that redacts the formatted message and the context data
 * (MDC) of every event before any appender sees it, whatever its layout. Values
 * in the context data stored under a sensitive key, such as {@code password},
 * are replaced whole.
 *
 * <pre>{@code
 * <Rewrite name="Redacted">
 *   <FlareRedact options='{"enable":["phone"]}'/>
 *   <AppenderRef ref="Console"/>
 * </Rewrite>
 * }</pre>
 *
 * The message of an attached exception is not rewritten (a {@code Throwable} is
 * not safely copyable); render exceptions through {@code %redact{%throwable}} in
 * the layout when they can carry data.
 */
@Plugin(name = "FlareRedact", category = Core.CATEGORY_NAME, elementType = "rewritePolicy", printObject = true)
public final class RedactRewritePolicy implements RewritePolicy {
    private final Policy policy;

    private RedactRewritePolicy(Policy policy) {
        this.policy = policy;
    }

    /**
     * @param options options in the JSON wire format; blank uses the shared policy
     * @return the rewrite policy
     */
    @PluginFactory
    public static RedactRewritePolicy createPolicy(@PluginAttribute("options") String options) {
        return new RedactRewritePolicy(FlareRedactLog4j.resolve(options));
    }

    /**
     * @param policy the policy to redact with
     * @return the rewrite policy
     */
    public static RedactRewritePolicy of(Policy policy) {
        return new RedactRewritePolicy(policy);
    }

    @Override
    public LogEvent rewrite(LogEvent source) {
        Log4jLogEvent.Builder builder = new Log4jLogEvent.Builder(source);
        builder.setMessage(redactMessage(source.getMessage()));
        Map<String, String> context = source.getContextData().toMap();
        if (!context.isEmpty()) {
            StringMap redacted = new SortedArrayStringMap(context.size());
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> out = (Map<String, Object>) policy.redact(context);
                for (Map.Entry<String, Object> entry : out.entrySet()) {
                    redacted.putValue(entry.getKey(), entry.getValue());
                }
            } catch (FlareRedactException error) {
                for (String key : context.keySet()) {
                    redacted.putValue(key, FlareRedactLog4j.WITHHELD);
                }
            }
            builder.setContextData(redacted);
        }
        return builder.build();
    }

    private Message redactMessage(Message message) {
        if (message == null) {
            return null;
        }
        try {
            if (message instanceof MapMessage) {
                @SuppressWarnings("unchecked")
                Map<String, Object> out = (Map<String, Object>) policy.redact(printable(((MapMessage<?, ?>) message).getData(), 0));
                MapMessage<?, Object> copy = new MapMessage<>(out);
                return copy;
            }
            return new SimpleMessage(policy.redactString(message.getFormattedMessage()));
        } catch (FlareRedactException error) {
            return new SimpleMessage(FlareRedactLog4j.WITHHELD);
        }
    }

    /**
     * A {@code MapMessage} prints its values with {@code String.valueOf}. The
     * walker rewrites strings, maps, collections and arrays and returns anything
     * else unchanged, so a {@code URI} or an object with its own
     * {@code toString} is turned into that text first, where the key rules and
     * detectors can see it.
     */
    private static Object printable(Object value, int depth) {
        if (value == null || value instanceof String || value instanceof Number
                || value instanceof Boolean || value instanceof Character) {
            return value;
        }
        if (depth < 64 && value instanceof Map) {
            Map<Object, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                out.put(entry.getKey(), printable(entry.getValue(), depth + 1));
            }
            return out;
        }
        if (depth < 64 && value instanceof Collection) {
            List<Object> out = new ArrayList<>();
            for (Object item : (Collection<?>) value) {
                out.add(printable(item, depth + 1));
            }
            return out;
        }
        if (depth < 64 && value instanceof Object[]) {
            Object[] in = (Object[]) value;
            Object[] out = new Object[in.length];
            for (int i = 0; i < in.length; i++) {
                out[i] = printable(in[i], depth + 1);
            }
            return out;
        }
        return String.valueOf(value);
    }

    @Override
    public String toString() {
        return "FlareRedact";
    }
}
