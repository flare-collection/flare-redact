package io.github.flarecollection.redact;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A value under a sensitive key is masked whatever its type (SPEC §9): numbers,
 * binary data, characters and every string or number inside a map, collection
 * or array at any depth. Booleans and null are kept.
 */
class SensitiveValuesTest {
    private static Map<String, Object> map(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            out.put((String) pairs[i], pairs[i + 1]);
        }
        return out;
    }

    @Test
    void numbersAndContainersUnderASensitiveKeyAreMasked() {
        Object out = FlareRedact.redact(map(
            "cvv", 123,
            "amount", 1000,
            "cookie", map("name", "connect.sid", "value", "s%3A_SID_abc"),
            "password", Arrays.asList("hunter2", Arrays.asList("letmein", 7.5)),
            "credentials", map("hash", "$argon2id$v=19$abc", "params", map("cost", 12L), "rotated", true),
            "hasPassword", true,
            "token", null));
        assertEquals(map(
            "cvv", "***",
            "amount", 1000,
            "cookie", map("name", "***", "value", "***"),
            "password", Arrays.asList("***", Arrays.asList("***", "***")),
            "credentials", map("hash", "***", "params", map("cost", "***"), "rotated", true),
            "hasPassword", true,
            "token", null), out);
    }

    @Test
    void binaryCharactersAndPrimitiveArraysAreMasked() {
        Map<?, ?> out = (Map<?, ?>) FlareRedact.redact(map(
            "privateKey", new byte[] {1, 2, (byte) 255},
            "password", "hunter2".toCharArray(),
            "pin", new int[] {1234, 5678},
            "data", new byte[] {9}));
        assertEquals("***", out.get("privateKey"));
        assertEquals("***", out.get("password"));
        assertArrayEquals(new Object[] {"***", "***"}, (Object[]) out.get("pin"));
        assertArrayEquals(new byte[] {9}, (byte[]) out.get("data"), "binary elsewhere is kept");

        Policy hash = Policy.compile(RedactOptions.builder().mode(Mode.HASH).transformSecret("k").build());
        assertEquals(hash.redact(map("secret", "0102ff", "pin", "1234")),
            hash.redact(map("secret", new byte[] {1, 2, (byte) 255}, "pin", new BigInteger("1234"))));
    }

    @Test
    void uuidsAreMaskedAsTheirText() {
        java.util.UUID key = java.util.UUID.fromString("0f8fad5b-d9cb-469f-a165-70867728950e");
        assertEquals(map("api_key", "***", "request_id", key), FlareRedact.redact(map("api_key", key, "request_id", key)));
        Policy hash = Policy.compile(RedactOptions.builder().mode(Mode.HASH).transformSecret("k").build());
        assertEquals(hash.redact(map("api_key", key.toString())), hash.redact(map("api_key", key)));
    }

    private static final class Login {
        @Override
        public String toString() {
            return "Login[user=ada, password=hunter2]";
        }
    }

    @Test
    void objectsTheWalkerCannotOpenAreMaskedAsText() {
        java.time.Instant when = java.time.Instant.EPOCH;
        assertEquals(map("credentials", "***", "token", when, "secret", "***"),
            FlareRedact.redact(map("credentials", new Login(), "token", when,
                "secret", java.util.Optional.of("hunter2"))));
        Policy policy = Policy.compile(RedactOptions.builder().includeValues(true).build());
        assertEquals("Login[user=ada, password=hunter2]", policy.scan(map("credentials", new Login())).get(0).value());
    }

    @Test
    void anAllowlistedNumberIsKept() {
        Policy policy = Policy.compile(RedactOptions.builder().allow("1234").build());
        assertEquals(map("pin", 1234, "cvv", "***"), policy.redact(map("pin", 1234, "cvv", 123)));
    }

    @Test
    void aSharedObjectKeepsItsCopiesApart() {
        Map<String, Object> shared = map("value", "abc");
        Map<?, ?> out = (Map<?, ?>) FlareRedact.redact(map("a", shared, "cookie", shared, "b", shared));
        assertEquals(map("value", "abc"), out.get("a"));
        assertEquals(map("value", "***"), out.get("cookie"));
        assertSame(out.get("a"), out.get("b"));
    }

    @Test
    void floatTextMatchesEcmaScript() {
        double[] values = {1.5, 0.1, 1e-7, 1.2e-5, 1e21, 1.5e21, 1e16, 100.0, 123456789012345680000.0,
            0.1 + 0.2, 5e-324, -42.25, -0.0, Double.NaN, Double.NEGATIVE_INFINITY, 2e-3};
        String[] texts = {"1.5", "0.1", "1e-7", "0.000012", "1e+21", "1.5e+21", "10000000000000000", "100",
            "123456789012345680000", "0.30000000000000004", "5e-324", "-42.25", "0", "NaN", "-Infinity", "0.002"};
        for (int i = 0; i < values.length; i++) {
            assertEquals(texts[i], SensitiveValues.jsFloat(values[i], false), String.valueOf(values[i]));
        }
        assertEquals("1.1", SensitiveValues.text(1.1f));
        assertEquals("1234", SensitiveValues.text(new BigDecimal("1234.000")));
        assertEquals("1.5", SensitiveValues.text(new BigDecimal("1.50")));
    }

    @Test
    void scanReportsEveryValueInside() {
        Policy policy = Policy.compile(RedactOptions.builder().includeValues(true).build());
        List<String> got = new ArrayList<>();
        for (Finding finding : policy.scan(map("cvv", 123, "cookie", map("name", "sid", "secure", true), "ok", 1))) {
            got.add(finding.detector() + " " + finding.path() + " " + finding.value());
        }
        assertEquals(Arrays.asList("sensitive_key cvv 123", "sensitive_key cookie.name sid"), got);
    }

    @Test
    void aVaultMintsAndRestoresSensitiveValues() {
        Vault vault = Vault.create(RedactOptions.defaults(), VaultOptions.readablePlaceholders());
        Object out = vault.redact(map("otp", 482913, "cookie", map("value", "abc")));
        assertEquals(map("otp", "[SENSITIVE_KEY_1]", "cookie", map("value", "[SENSITIVE_KEY_2]")), out);
        assertEquals(map("otp", "482913", "cookie", map("value", "abc")), vault.restore(out));
    }
}
