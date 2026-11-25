package io.github.flarecollection.redact;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Restores placeholders in a stream, even when one is split across chunks. It
 * holds back the longest suffix of what it has buffered that could still be the
 * start of a placeholder; everything before that is emitted at once.
 *
 * <p>Not thread-safe: one restorer belongs to one stream.
 */
public final class StreamRestorer {
    private final Function<String, String> restore;
    private final List<String> placeholders = new ArrayList<>();
    private final StringBuilder buffer = new StringBuilder();

    /**
     * @param entries placeholder, original pairs
     */
    public StreamRestorer(List<Map.Entry<String, String>> entries) {
        this.restore = Restorers.plain(entries);
        for (Map.Entry<String, String> entry : entries) {
            placeholders.add(entry.getKey());
        }
    }

    private int pendingPrefixLength() {
        int keep = 0;
        for (String placeholder : placeholders) {
            int limit = Math.min(buffer.length(), placeholder.length() - 1);
            for (int length = limit; length > keep; length--) {
                if (endsWith(placeholder, length)) {
                    keep = length;
                    break;
                }
            }
        }
        return keep;
    }

    private boolean endsWith(String placeholder, int length) {
        int offset = buffer.length() - length;
        for (int i = 0; i < length; i++) {
            if (buffer.charAt(offset + i) != placeholder.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Feed a chunk.
     *
     * @param chunk the next piece of the stream
     * @return the text that is safe to show now, restored
     */
    public String push(String chunk) {
        buffer.append(chunk);
        int cut = buffer.length() - pendingPrefixLength();
        String emit = buffer.substring(0, cut);
        buffer.delete(0, cut);
        return restore.apply(emit);
    }

    /** @return whatever is still held back, once the stream has ended */
    public String flush() {
        String out = restore.apply(buffer.toString());
        buffer.setLength(0);
        return out;
    }
}
