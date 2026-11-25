package io.github.flarecollection.redact.logback;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import ch.qos.logback.core.encoder.EncoderBase;
import io.github.flarecollection.redact.Json;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

class LogbackTest {
    private static String run(LoggerContext context, PatternLayoutEncoder pattern, EncoderBase<ILoggingEvent> wrapper,
                              String message, Object... args) {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        OutputStreamAppender<ILoggingEvent> appender = new OutputStreamAppender<>();
        appender.setContext(context);
        appender.setEncoder(wrapper != null ? wrapper : pattern);
        appender.setOutputStream(sink);
        appender.start();
        Logger logger = context.getLogger("test");
        logger.detachAndStopAllAppenders();
        logger.setAdditive(false);
        logger.addAppender(appender);
        logger.info(message, args);
        appender.stop();
        return new String(sink.toByteArray(), StandardCharsets.UTF_8);
    }

    private static LoggerContext newContext() {
        LoggerContext context = new LoggerContext();
        context.setMDCAdapter(new ch.qos.logback.classic.util.LogbackMDCAdapter());
        return context;
    }

    @Test
    void converterRedactsTheRenderedMessage() {
        LoggerContext context = newContext();
        context.putObject(ch.qos.logback.core.CoreConstants.PATTERN_RULE_REGISTRY,
            new java.util.HashMap<>(Map.of("redact", RedactingConverter.class.getName())));
        PatternLayoutEncoder pattern = new PatternLayoutEncoder();
        pattern.setContext(context);
        pattern.setPattern("%redact(%msg){'{\"mode\":\"label\"}'}%n");
        pattern.start();
        String out = run(context, pattern, null, "login {} with key {}", "ada@example.com", "AKIAIOSFODNN7EXAMPLE");
        assertEquals("login [REDACTED:email] with key [REDACTED:aws_access_key]" + System.lineSeparator(), out);
    }

    @Test
    void encoderRedactsJsonLinesStructurally() {
        LoggerContext context = newContext();
        PatternLayoutEncoder pattern = new PatternLayoutEncoder();
        pattern.setContext(context);
        pattern.setPattern("{\"msg\":\"%msg\",\"password\":\"hunter2\"}%n");
        pattern.start();
        RedactingEncoder encoder = new RedactingEncoder();
        encoder.setContext(context);
        encoder.setEncoder(pattern);
        encoder.start();
        String out = run(context, pattern, encoder, "mail ada@example.com");
        Map<?, ?> line = (Map<?, ?>) Json.parse(out.trim());
        assertEquals("***", line.get("password"));
        assertFalse(String.valueOf(line.get("msg")).contains("ada@example.com"), out);
        assertTrue(out.endsWith(System.lineSeparator()));
    }

    @Test
    void encoderWorksFromXmlConfiguration() throws Exception {
        LoggerContext context = newContext();
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(context);
        String xml = "<configuration>"
            + "<appender name=\"OUT\" class=\"ch.qos.logback.core.FileAppender\">"
            + "<file>" + System.getProperty("java.io.tmpdir") + "/flare-redact-logback-test.log</file>"
            + "<append>false</append>"
            + "<encoder class=\"io.github.flarecollection.redact.logback.RedactingEncoder\">"
            + "<options>{\"mask\":\"#\"}</options>"
            + "<encoder class=\"ch.qos.logback.classic.encoder.PatternLayoutEncoder\"><pattern>%msg%n</pattern></encoder>"
            + "</encoder></appender>"
            + "<root level=\"INFO\"><appender-ref ref=\"OUT\"/></root></configuration>";
        configurator.doConfigure(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        context.getLogger("x").info("token for ada@example.com");
        context.stop();
        String written = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(
            System.getProperty("java.io.tmpdir"), "flare-redact-logback-test.log")), StandardCharsets.UTF_8);
        assertEquals("token for #" + System.lineSeparator(), written);
    }
}
