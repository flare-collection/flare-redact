package io.github.flarecollection.redact.log4j2;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;

/** Keeps formatted lines in memory, for the tests. */
@Plugin(name = "Memory", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE)
public final class MemoryAppender extends AbstractAppender {
    final List<String> lines = new CopyOnWriteArrayList<>();

    private MemoryAppender(String name, Layout<?> layout) {
        super(name, null, layout, true, Property.EMPTY_ARRAY);
    }

    @PluginFactory
    public static MemoryAppender create(@PluginAttribute("name") String name,
                                        @PluginElement("Layout") Layout<?> layout) {
        return new MemoryAppender(name, layout);
    }

    @Override
    public void append(LogEvent event) {
        lines.add(new String(getLayout().toByteArray(event), java.nio.charset.StandardCharsets.UTF_8));
    }
}
