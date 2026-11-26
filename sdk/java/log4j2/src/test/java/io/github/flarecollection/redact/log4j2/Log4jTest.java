package io.github.flarecollection.redact.log4j2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.message.MapMessage;
import org.apache.logging.log4j.message.StringMapMessage;
import org.junit.jupiter.api.Test;

class Log4jTest {
    private static MemoryAppender appender(String name) {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        MemoryAppender appender = context.getConfiguration().getAppender(name);
        appender.lines.clear();
        return appender;
    }

    @Test
    void patternConverterRedactsTheRenderedMessage() {
        MemoryAppender memory = appender("Pattern");
        LogManager.getLogger("pattern").info("login {} key {}", "ada@example.com", "AKIAIOSFODNN7EXAMPLE");
        assertEquals("login [REDACTED:email] key [REDACTED:aws_access_key]", memory.lines.get(0));
    }

    @Test
    void rewritePolicyRedactsMessageAndContext() {
        MemoryAppender memory = appender("Plain");
        ThreadContext.put("password", "hunter2");
        ThreadContext.put("note", "mail grace@example.org");
        try {
            LogManager.getLogger("rewrite").info("mail {}", "ada@example.com");
        } finally {
            ThreadContext.clearMap();
        }
        String line = memory.lines.get(0);
        assertEquals(3, line.split("\\|", -1).length, line);
        String[] parts = line.split("\\|", -1);
        assertEquals(false, parts[0].contains("ada@example.com"), line);
        assertEquals("***", parts[1]);
        assertEquals(false, parts[2].contains("grace@example.org"), line);
    }

    @Test
    void rewritePolicyRedactsMapMessages() {
        MemoryAppender memory = appender("Plain");
        Map<String, String> data = new HashMap<>();
        data.put("password", "hunter2");
        LogManager.getLogger("rewrite").info(new StringMapMessage(data));
        assertEquals("password=\"***\"||", memory.lines.get(0));
    }

    @Test
    void rewritePolicyRedactsObjectValuesInMapMessages() {
        MemoryAppender memory = appender("Plain");
        String dsn = "postgres://admin:s3cr3tPassw0rd@db.internal:5432/app";
        Object connection = new Object() {
            @Override
            public String toString() {
                return "conn " + dsn;
            }
        };
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("url", URI.create(dsn));
        data.put("count", 3);
        data.put("nested", Collections.singletonMap("conn", connection));
        LogManager.getLogger("rewrite").info(new MapMessage<>(data));
        String line = memory.lines.get(0);
        assertFalse(line.contains("s3cr3tPassw0rd"), line);
        assertTrue(line.contains("count=\"3\""), line);
        assertTrue(line.contains("conn postgres://admin:"), line);
    }
}
