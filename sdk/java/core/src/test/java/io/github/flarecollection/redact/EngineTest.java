package io.github.flarecollection.redact;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EngineTest {
    private static final String SMILE = new String(Character.toChars(0x1F600));

    private static String repeat(String s, int n) {
        StringBuilder out = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            out.append(s);
        }
        return out.toString();
    }

    private static Pack pack(String detector) {
        return Pack.load("{\"spec\":\"FRS-1\",\"id\":\"test\",\"version\":\"1\",\"detectors\":[" + detector + "]}");
    }

    private static String detector(String pattern) {
        return "{\"id\":\"t\",\"label\":\"T\",\"why\":\"w\",\"pattern\":" + Json.stringify(pattern)
            + ",\"mask\":{\"type\":\"fixed\"},\"default\":true,\"risk\":\"high\",\"confidence\":0.9}";
    }

    @Test
    void masksTheDefaults() {
        String out = FlareRedact.redactString("contact ada@example.com now");
        assertFalse(out.contains("ada@example.com"), out);
        assertTrue(out.startsWith("contact ") && out.endsWith(" now"), out);
        assertTrue(FlareRedact.isClean("the quick brown fox"));
        assertFalse(FlareRedact.isClean("AKIAIOSFODNN7EXAMPLE"));
    }

    @Test
    void inputLimitCountsUtf16Units() {
        String text = "üüüü" + SMILE + SMILE;
        assertEquals(8, text.length());
        Policy fits = Policy.compile(RedactOptions.builder().maxInputLength(8).build());
        assertEquals(text, fits.redactString(text));
        Policy over = Policy.compile(RedactOptions.builder().maxInputLength(7).build());
        assertThrows(RedactionLimitException.class, () -> over.redactString(text));
    }

    @Test
    void tooManyFindingsFailClosed() {
        Policy policy = Policy.compile(RedactOptions.builder().maxFindings(3).build());
        String text = repeat("ada@example.com ", 4);
        assertThrows(RedactionLimitException.class, () -> policy.redactString(text));
    }

    @Test
    void regexStackExhaustionFailsClosed() {
        Policy policy = Policy.compile(RedactOptions.builder().pack(pack(detector("(?:a|b)+x"))).build());
        String text = repeat("ab", 1_000_000);
        assertThrows(RedactionLimitException.class, () -> policy.redactString(text));
    }

    @Test
    void keyedModesNeedASecret() {
        assertThrows(FlareRedactException.class,
            () -> Policy.compile(RedactOptions.builder().mode(Mode.HASH).build()));
        Policy hash = Policy.compile(RedactOptions.builder().mode(Mode.HASH).transformSecret("k").build());
        String out = hash.redactString("mail ada@example.com");
        assertTrue(out.matches("mail email_[0-9a-f]{32}"), out);
        assertEquals(out, hash.redactString("mail ada@example.com"));
    }

    @Test
    void labelAndFixedMasks() {
        Policy label = Policy.compile(RedactOptions.builder().mode(Mode.LABEL).build());
        assertEquals("mail [REDACTED:email]", label.redactString("mail ada@example.com"));
        Policy fixed = Policy.compile(RedactOptions.builder().mask("#").build());
        assertEquals("mail #", fixed.redactString("mail ada@example.com"));
        Policy custom = Policy.compile(RedactOptions.builder()
            .maskFunction((value, d) -> "<" + d.id() + ":" + value.length() + ">").build());
        assertEquals("mail <email:15>", custom.redactString("mail ada@example.com"));
    }

    @Test
    void zeroWidthSplicesAreCovered() {
        String spliced = "key AKIA​IOSFODNN7EXAMPLE end";
        String out = FlareRedact.redactString(spliced);
        assertFalse(out.contains("IOSFODNN7"), out);
        assertTrue(out.startsWith("key ") && out.endsWith(" end"), out);
    }

    @Test
    void termsRespectUnicodeWordBoundaries() {
        Policy policy = Policy.compile(RedactOptions.builder()
            .terms(Arrays.asList(Term.of("Bluebird"), Term.of("istanbul", "[CITY]"), Term.of("café"))).build());
        assertEquals("*** and Bluebirds", policy.redactString("Bluebird and Bluebirds"));
        assertEquals("[CITY]!", policy.redactString("İSTANBUL!"));
        // A combining mark or an astral letter next to the term makes it part of a word.
        String astral = new String(Character.toChars(0x10400));
        assertEquals("bluebird́", policy.redactString("bluebird́"));
        assertEquals(astral + "bluebird", policy.redactString(astral + "bluebird"));
        assertEquals(SMILE + "***", policy.redactString(SMILE + "bluebird"));
    }

    @Test
    void termsCanBeCaseSensitive() {
        Policy policy = Policy.compile(RedactOptions.builder().terms("Atlas").termsCaseSensitive(true).build());
        assertEquals("*** atlas", policy.redactString("Atlas atlas"));
    }

    @Test
    void caseFoldingUsesTheBundledTable() {
        assertTrue(Arrays.stream(CaseFolding.orbit('k')).anyMatch(c -> c == 0x212A), "Kelvin sign");
        assertArrayEquals(new int[] {'I', 'i', 0x130, 0x131}, CaseFolding.orbit(0x131));
        assertNotNull(CaseFolding.orbit(0x1C89), "Unicode 16 additions are present on every JDK");
        assertNull(CaseFolding.orbit('1'));
        Policy policy = Policy.compile(RedactOptions.builder().pack(pack(
            "{\"id\":\"t\",\"label\":\"T\",\"why\":\"w\",\"pattern\":\"secret[0-9]\",\"flags\":\"i\","
                + "\"mask\":{\"type\":\"fixed\"},\"default\":true,\"risk\":\"high\",\"confidence\":0.9}")).build());
        assertEquals("*** ***", policy.redactString("SECRET1 ſecret2"));
    }

    @Test
    void sensitiveKeysAreNormalised() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("PASSWORD", "hunter2");
        input.put("Şifrə", "x1");
        input.put("Passwort", "x2");
        input.put("note", "fine");
        Map<?, ?> out = (Map<?, ?>) FlareRedact.redact(input);
        assertEquals("***", out.get("PASSWORD"));
        assertEquals("***", out.get("Şifrə"));
        assertEquals("***", out.get("Passwort"));
        assertEquals("fine", out.get("note"));

        Policy names = Policy.compile(RedactOptions.builder().keyNames("internal_id").build());
        Map<String, Object> custom = new LinkedHashMap<>();
        custom.put("INTERNAL_ID", "42");
        custom.put("password", "kept");
        Map<?, ?> redacted = (Map<?, ?>) names.redact(custom);
        assertEquals("***", redacted.get("INTERNAL_ID"));
        assertEquals("kept", redacted.get("password"));

        Policy none = Policy.compile(RedactOptions.builder().keyNames(Collections.emptyList()).build());
        assertEquals("kept", ((Map<?, ?>) none.redact(custom)).get("password"));
    }

    @Test
    void scanReportsPathsAndPositions() {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("email", "x ada@example.com");
        user.put("password", "hunter2");
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("user", user);
        input.put("items", Arrays.asList("a", "line one\nmail grace@example.org"));
        List<Finding> findings = Policy.compile(RedactOptions.builder().includeValues(true).build()).scan(input);
        assertEquals(3, findings.size());
        assertEquals("user.email", findings.get(0).path());
        assertEquals(2, findings.get(0).start());
        assertEquals("ada@example.com", findings.get(0).value());
        assertEquals("user.password", findings.get(1).path());
        assertEquals(-1, findings.get(1).start());
        assertEquals("sensitive_key", findings.get(1).detector());
        assertEquals("items[1]", findings.get(2).path());
        assertEquals(2, findings.get(2).line());
        assertEquals(6, findings.get(2).column());
        assertNull(FlareRedact.scan(input).get(0).value(), "values are left out by default");
        Summary summary = FlareRedact.summarize(input);
        assertEquals(3, summary.total());
        assertEquals(Integer.valueOf(2), summary.byDetector().get("email"));
    }

    @Test
    void structuredValuesKeepTheirShapeAndCycles() {
        Map<String, Object> node = new LinkedHashMap<>();
        List<Object> list = new ArrayList<>();
        list.add("ada@example.com");
        list.add(list);
        node.put("list", list);
        node.put("n", 42);
        node.put("arr", new String[] {"grace@example.org"});
        Map<?, ?> out = (Map<?, ?>) FlareRedact.redact(node);
        List<?> outList = (List<?>) out.get("list");
        assertFalse(String.valueOf(outList.get(0)).contains("ada@"));
        assertSame(outList, outList.get(1));
        assertEquals(42, out.get("n"));
        assertTrue(out.get("arr") instanceof String[]);
        assertEquals(1, FlareRedact.scan(list).size());
    }

    @Test
    void redactJsonRoundTrips() {
        String out = FlareRedact.defaultPolicy().redactJson("{\"to\":\"ada@example.com\",\"password\":\"x\",\"n\":1.5}");
        Map<?, ?> parsed = (Map<?, ?>) Json.parse(out);
        assertEquals("***", parsed.get("password"));
        assertEquals(1.5, ((Number) parsed.get("n")).doubleValue());
        assertFalse(out.contains("ada@example.com"));
    }

    @Test
    void vaultRoundTripsWithOpaquePlaceholders() {
        Vault vault = Vault.create(RedactOptions.defaults());
        String redacted = vault.redactString("mail ada@example.com or ada@example.com");
        assertTrue(redacted.matches("mail \\[FR_EMAIL_[0-9a-f]{24}] or \\[FR_EMAIL_[0-9a-f]{24}]"), redacted);
        assertEquals(1, vault.size());
        assertEquals("mail ada@example.com or ada@example.com", vault.restoreString(redacted));
    }

    @Test
    void vaultRefusesDuplicatePlaceholders() {
        Vault vault = Vault.create(RedactOptions.defaults(), VaultOptions.customPlaceholders((id, n) -> "[X]"));
        assertThrows(FlareRedactException.class, () -> vault.redactString("ada@example.com grace@example.org"));
    }

    @Test
    void restoringIntoJsonEscapesOriginals() {
        Vault vault = Vault.create(RedactOptions.builder().terms("Q\"uo").build(), VaultOptions.readablePlaceholders());
        assertEquals("say [CUSTOM_TERM_1]", vault.redactString("say Q\"uo"));
        assertEquals("[\"Q\\\"uo\", 1]", vault.restoreString("[\"[CUSTOM_TERM_1]\", 1]"));
        assertEquals("said Q\"uo", vault.restoreString("said [CUSTOM_TERM_1]"));
        assertTrue(Restorers.isJsonDocument(" {\"a\":1}"));
        assertFalse(Restorers.isJsonDocument("{ not json"));
    }

    @Test
    void streamRestorerHandlesSplitPlaceholders() {
        Session session = new Session(RedactOptions.defaults(), VaultOptions.readablePlaceholders());
        assertEquals("write to [EMAIL_1]", session.redactString("write to ada@example.com"));
        StreamRestorer stream = session.stream();
        StringBuilder out = new StringBuilder();
        for (String chunk : new String[] {"Sure, [EM", "AIL", "_1] is", " set [EMA"}) {
            out.append(stream.push(chunk));
        }
        out.append(stream.flush());
        assertEquals("Sure, ada@example.com is set [EMA", out.toString());
        session.reset();
        assertEquals(0, session.vault().size());
    }

    @Test
    void wireOptionsRoundTrip() {
        RedactOptions options = RedactOptions.fromJson("{\"enable\":[\"phone\"],\"mode\":\"label\",\"redactKeys\":[\"a\"],"
            + "\"terms\":{\"Atlas\":\"[P]\",\"Orion\":\"[Q]\"},\"minConfidence\":0.5,\"limits\":{\"maxFindings\":10}}");
        assertEquals(Mode.LABEL, options.mode());
        assertEquals(10, options.maxFindings());
        assertEquals(options.toJson(), RedactOptions.fromJson(options.toJson()).toJson());
        assertThrows(IllegalArgumentException.class, () -> RedactOptions.fromJson("{\"nope\":1}"));
        assertThrows(IllegalArgumentException.class, () -> RedactOptions.fromJson("{\"only\":\"email\"}"));
    }

    @Test
    void packLoadingIsStrict() {
        assertThrows(PackException.class, () -> pack(detector("(?=a)b")));
        assertThrows(PackException.class, () -> pack(detector("\\d+")));
        assertThrows(PackException.class, () -> pack(detector("a*")));
        assertThrows(PackException.class, () -> pack(detector("^a")));
        assertThrows(PackException.class, () -> pack(
            "{\"id\":\"t\",\"label\":\"T\",\"why\":\"w\",\"pattern\":\"a\",\"validators\":[{\"name\":\"nope\"}],"
                + "\"mask\":{\"type\":\"fixed\"},\"default\":true,\"risk\":\"high\",\"confidence\":0.9}"));
        assertThrows(PackException.class, () -> Pack.load("{\"spec\":\"FRS-2\",\"detectors\":[]}"));
        assertEquals(120, Pack.core().detectors().size());
    }

    @Test
    void firstUnitFilterMatchesTheFullScan() {
        String[] patterns = {"[A-Z]{2}[0-9]{2}", "(?:ab|cd)+e", "[^a-z]x", "{{L}}{3}", "(?:x)?y", "\\x41\\u00e9"};
        String subject = "xx AB12 abcde cdabe 9x Éx" + SMILE + "x Aé café y xy";
        for (String source : patterns) {
            for (String flags : new String[] {"", "i"}) {
                Pattern compiled = Pattern.of(source, flags);
                List<String> fast = new ArrayList<>();
                for (int[] span : compiled.withFirst.spans(subject)) {
                    fast.add(span[0] + "-" + span[1]);
                }
                List<String> slow = new ArrayList<>();
                for (int[] span : compiled.without.spans(subject)) {
                    slow.add(span[0] + "-" + span[1]);
                }
                assertEquals(slow, fast, source + " /" + flags);
            }
        }
    }

    /** One pattern compiled twice: with and without the first-unit filter. */
    private static final class Pattern {
        final Detector withFirst;
        final Detector without;

        private Pattern(Detector withFirst, Detector without) {
            this.withFirst = withFirst;
            this.without = without;
        }

        static Pattern of(String source, String flags) {
            Detector.Builder fast = new Detector.Builder();
            fast.pattern = Pack.compile(source, flags, "test", true);
            fast.first = FirstSet.of(source, flags.equals("i"));
            Detector.Builder slow = new Detector.Builder();
            slow.pattern = fast.pattern;
            return new Pattern(new Detector(fast), new Detector(slow));
        }
    }
}
