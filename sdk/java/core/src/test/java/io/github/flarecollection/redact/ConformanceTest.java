package io.github.flarecollection.redact;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The Java engine must agree with the JavaScript, Python, Go and Rust engines,
 * case for case (SPEC §13). This file is the Java half of that promise.
 */
class ConformanceTest {
    static Path specDir() {
        String configured = System.getProperty("flare.spec.dir");
        Path dir = configured != null ? Paths.get(configured) : Paths.get("..", "..", "..", "spec");
        return dir.toAbsolutePath().normalize();
    }

    static Object readJson(Path path) throws IOException {
        return Json.parse(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
    }

    private static double round6(double value) {
        return Math.round(value * 1e6) / 1e6;
    }

    private static Map<String, Object> normalise(Finding finding) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("detector", finding.detector());
        out.put("risk", finding.risk().wireName());
        out.put("confidence", round6(finding.confidence()));
        if (finding.start() >= 0) {
            out.put("start", (long) finding.start());
            out.put("end", (long) finding.end());
            out.put("line", (long) finding.line());
            out.put("column", (long) finding.column());
        }
        if (finding.path() != null) {
            out.put("path", finding.path());
        }
        if (finding.value() != null) {
            out.put("value", finding.value());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> runCase(Map<String, Object> testCase) {
        Object input = testCase.get("input");
        RedactOptions options = RedactOptions.fromWire((Map<String, Object>) testCase.get("options"));
        List<Object> checks = testCase.get("checks") instanceof List
            ? (List<Object>) testCase.get("checks")
            : Arrays.asList("redact", "scan");
        Map<String, Object> result = new LinkedHashMap<>();
        if (checks.contains("redact")) {
            result.put("redact", Policy.compile(options).redact(input));
        }
        if (checks.contains("scan")) {
            List<Object> findings = new ArrayList<>();
            for (Finding finding : Policy.compile(options).scan(input)) {
                findings.add(normalise(finding));
            }
            result.put("findings", findings);
        }
        if (checks.contains("vault")) {
            Map<String, Object> spec = testCase.get("vault") instanceof Map
                ? (Map<String, Object>) testCase.get("vault")
                : new LinkedHashMap<>();
            VaultOptions style = "readable".equals(spec.get("placeholderStyle"))
                ? VaultOptions.readablePlaceholders()
                : VaultOptions.opaquePlaceholders();
            Vault vault = Vault.create(options, style);
            Object redacted = vault.redact(input);
            List<Object> entries = new ArrayList<>();
            for (Map.Entry<String, String> entry : vault.entries()) {
                entries.add(Arrays.asList(entry.getKey(), entry.getValue()));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("redacted", redacted);
            out.put("restored", vault.restore(redacted));
            out.put("entries", entries);
            if (spec.containsKey("reply")) {
                out.put("reply", vault.restore(spec.get("reply")));
            }
            result.put("vault", out);
        }
        return result;
    }

    /** Structural equality with every number compared as a double, as JSON has one number type. */
    static boolean jsonEquals(Object a, Object b) {
        if (a instanceof Number && b instanceof Number) {
            return ((Number) a).doubleValue() == ((Number) b).doubleValue();
        }
        if (a instanceof Map && b instanceof Map) {
            Map<?, ?> left = (Map<?, ?>) a;
            Map<?, ?> right = (Map<?, ?>) b;
            if (left.size() != right.size()) {
                return false;
            }
            for (Map.Entry<?, ?> entry : left.entrySet()) {
                if (!right.containsKey(entry.getKey()) || !jsonEquals(entry.getValue(), right.get(entry.getKey()))) {
                    return false;
                }
            }
            return true;
        }
        if (a instanceof List && b instanceof List) {
            List<?> left = (List<?>) a;
            List<?> right = (List<?>) b;
            if (left.size() != right.size()) {
                return false;
            }
            Iterator<?> l = left.iterator();
            Iterator<?> r = right.iterator();
            while (l.hasNext()) {
                if (!jsonEquals(l.next(), r.next())) {
                    return false;
                }
            }
            return true;
        }
        return a == null ? b == null : a.equals(b);
    }

    @TestFactory
    @SuppressWarnings("unchecked")
    Stream<DynamicTest> corpus() throws IOException {
        Map<String, Object> corpus = (Map<String, Object>) readJson(specDir().resolve("conformance/cases.json"));
        Map<String, Object> expected = (Map<String, Object>) readJson(specDir().resolve("conformance/expected.json"));
        List<Object> cases = (List<Object>) corpus.get("cases");
        assertEquals(expected.size(), cases.size(), "cases.json and expected.json disagree on the case count");
        return cases.stream().map(item -> {
            Map<String, Object> testCase = (Map<String, Object>) item;
            String name = (String) testCase.get("name");
            return DynamicTest.dynamicTest(name, () -> {
                Object want = expected.get(name);
                if (want == null) {
                    fail("no expectation for " + name);
                }
                // A round trip through JSON gives both sides the same concrete types.
                Object got = Json.parse(Json.stringify(runCase(testCase)));
                if (!jsonEquals(got, want)) {
                    fail("mismatch\n got: " + Json.stringify(got) + "\nwant: " + Json.stringify(want));
                }
            });
        });
    }

    @Test
    void vendoredPackMatchesSpecification() throws IOException {
        Object canonical = readJson(specDir().resolve("detectors.json"));
        Object vendored;
        try (InputStream in = Pack.class.getResourceAsStream("detectors.json")) {
            assertTrue(in != null, "the bundled pack is missing");
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[16384];
            for (int n; (n = in.read(chunk)) > 0; ) {
                buffer.write(chunk, 0, n);
            }
            vendored = Json.parse(new String(buffer.toByteArray(), StandardCharsets.UTF_8));
        }
        assertTrue(jsonEquals(canonical, vendored),
            "the vendored pack has drifted from spec/detectors.json; run `npm run spec:sync`");
    }
}
