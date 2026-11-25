package io.github.flarecollection.redact.logback;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.encoder.Encoder;
import ch.qos.logback.core.encoder.EncoderBase;
import io.github.flarecollection.redact.FlareRedactException;
import io.github.flarecollection.redact.Policy;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Redacts whatever another encoder writes, so it works with any layout: a
 * pattern, a JSON encoder, your own. A line that is a JSON document is redacted
 * structurally, so a {@code "password"} field is caught by its name and the line
 * stays valid JSON; any other text is redacted as text.
 *
 * <pre>{@code
 * <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
 *   <encoder class="io.github.flarecollection.redact.logback.RedactingEncoder">
 *     <options>{"enable":["phone"]}</options>
 *     <encoder class="ch.qos.logback.classic.encoder.PatternLayoutEncoder">
 *       <pattern>%d %-5level %logger - %msg%n</pattern>
 *     </encoder>
 *   </encoder>
 * </appender>
 * }</pre>
 */
public class RedactingEncoder extends EncoderBase<ILoggingEvent> {
    private Encoder<ILoggingEvent> encoder;
    private String options;
    private Charset charset = StandardCharsets.UTF_8;
    private Policy policy;

    /** @param value the encoder whose output is redacted */
    public void setEncoder(Encoder<ILoggingEvent> value) {
        encoder = value;
    }

    /** @return the wrapped encoder */
    public Encoder<ILoggingEvent> getEncoder() {
        return encoder;
    }

    /** @param value options in the JSON wire format; blank uses the shared policy */
    public void setOptions(String value) {
        options = value;
    }

    /** @param value the charset the wrapped encoder writes; UTF-8 by default */
    public void setCharset(Charset value) {
        charset = value;
    }

    @Override
    public void start() {
        if (encoder == null) {
            addError("RedactingEncoder needs a nested <encoder>");
            return;
        }
        try {
            policy = FlareRedactLogback.resolve(options);
        } catch (RuntimeException error) {
            addError("invalid flare-redact options: " + error.getMessage(), error);
            return;
        }
        if (!encoder.isStarted()) {
            encoder.start();
        }
        super.start();
    }

    @Override
    public void stop() {
        if (encoder != null) {
            encoder.stop();
        }
        super.stop();
    }

    @Override
    public byte[] headerBytes() {
        return encoder == null ? null : encoder.headerBytes();
    }

    @Override
    public byte[] footerBytes() {
        return encoder == null ? null : encoder.footerBytes();
    }

    @Override
    public byte[] encode(ILoggingEvent event) {
        byte[] raw = encoder.encode(event);
        if (raw == null || raw.length == 0) {
            return raw;
        }
        return redact(new String(raw, charset)).getBytes(charset);
    }

    String redact(String text) {
        Policy active = policy != null ? policy : FlareRedactLogback.policy();
        try {
            StringBuilder out = new StringBuilder(text.length());
            int start = 0;
            while (start < text.length()) {
                int newline = text.indexOf('\n', start);
                int end = newline < 0 ? text.length() : newline;
                out.append(redactLine(active, text.substring(start, end)));
                if (newline < 0) {
                    break;
                }
                out.append('\n');
                start = newline + 1;
            }
            return out.toString();
        } catch (FlareRedactException error) {
            return RedactingConverter.WITHHELD + System.lineSeparator();
        }
    }

    private static String redactLine(Policy policy, String line) {
        String body = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
        String trimmed = body.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                return policy.redactJson(body) + line.substring(body.length());
            } catch (IllegalArgumentException notJson) {
                // Not a JSON document after all: redact it as text below.
            }
        }
        return policy.redactString(line);
    }
}
