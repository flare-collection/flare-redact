package io.github.flarecollection.redact;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The learned secret-confidence classifier (SPEC §6): a 14-feature logistic
 * regression whose weights ship inside the detector pack. It lets
 * {@code refineConfidence} push benign look-alikes (a git SHA, a UUID, a digest)
 * below a threshold instead of masking them.
 */
public final class ConfidenceModel {
    static final List<String> FEATURES = Collections.unmodifiableList(Arrays.asList(
        "log2Len", "entropy", "fracLower", "fracUpper", "fracDigit", "fracSymbol",
        "fracHex", "vowelFrac", "classTransitionRate", "hasMixedClasses",
        "maxRunFrac", "structuredHexId", "ctxSecret", "ctxBenign"));

    // Context words use ASCII-only case folding and ASCII word boundaries, so the
    // patterns are case-sensitive and run over an ASCII-lowered copy.
    private static final Pattern SECRET_CONTEXT = Pattern.compile(
        "(?<![A-Za-z0-9_])(?:secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer"
            + "|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)(?![A-Za-z0-9_])");
    private static final Pattern BENIGN_CONTEXT = Pattern.compile(
        "(?<![A-Za-z0-9_])(?:uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision"
            + "|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id|content[_-]?id"
            + "|version|colou?r|slug|filename)(?![A-Za-z0-9_])");
    private static final Pattern STRUCTURED_HEX = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24}"
            + "|[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}");

    private final int version;
    private final double[] weights;
    private final double bias;

    ConfidenceModel(int version, List<String> features, double[] weights, double bias) {
        if (weights.length != features.size()) {
            throw new PackException("confidence model has " + weights.length + " weights for "
                + features.size() + " features");
        }
        if (!features.equals(FEATURES)) {
            throw new PackException("confidence model features " + features + " do not match this engine's "
                + FEATURES);
        }
        this.version = version;
        this.weights = weights.clone();
        this.bias = bias;
    }

    /** @return the model version declared by the pack */
    public int version() {
        return version;
    }

    private static String asciiLower(String text) {
        char[] out = null;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                if (out == null) {
                    out = text.toCharArray();
                }
                out[i] = (char) (c + 32);
            }
        }
        return out == null ? text : new String(out);
    }

    private static boolean isVowel(char c) {
        return "aeiouAEIOU".indexOf(c) >= 0;
    }

    /** The feature vector for {@code value}, over UTF-16 code units as in JavaScript. */
    static double[] features(String value, String context) {
        int length = Math.max(1, value.length());
        int lower = 0, upper = 0, digit = 0, symbol = 0, hex = 0, vowel = 0, letters = 0;
        int transitions = 0, run = 1, maxRun = 1, previous = -1;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'a' && c <= 'z') {
                lower++;
                letters++;
            } else if (c >= 'A' && c <= 'Z') {
                upper++;
                letters++;
            } else if (c >= '0' && c <= '9') {
                digit++;
            } else {
                symbol++;
            }
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                hex++;
            }
            if (isVowel(c)) {
                vowel++;
            }
            int kind = c >= '0' && c <= '9' ? 1 : (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ? 0 : 2;
            if (previous == -1) {
                previous = kind;
            } else {
                if (kind != previous) {
                    transitions++;
                    run = 1;
                } else {
                    run++;
                }
                if (run > maxRun) {
                    maxRun = run;
                }
                previous = kind;
            }
        }
        String folded = asciiLower(context);
        double total = length;
        return new double[] {
            Checksums.log2(total),
            Checksums.shannonEntropy(value),
            lower / total,
            upper / total,
            digit / total,
            symbol / total,
            hex / total,
            letters > 0 ? (double) vowel / letters : 0,
            length > 1 ? (double) transitions / (length - 1) : 0,
            lower > 0 && upper > 0 && digit > 0 ? 1 : 0,
            maxRun / total,
            STRUCTURED_HEX.matcher(value).matches() ? 1 : 0,
            SECRET_CONTEXT.matcher(folded).find() ? 1 : 0,
            BENIGN_CONTEXT.matcher(folded).find() ? 1 : 0,
        };
    }

    /**
     * The probability in [0, 1] that {@code value} is a real secret rather than a
     * benign high-entropy look-alike.
     *
     * @param value the matched value
     * @param context the text around it, value included
     * @return the probability
     */
    public double secretProbability(String value, String context) {
        double[] x = features(value, context);
        double z = bias;
        for (int i = 0; i < weights.length; i++) {
            z += weights[i] * x[i];
        }
        return z >= 0 ? 1 / (1 + Math.exp(-z)) : Math.exp(z) / (1 + Math.exp(z));
    }
}
