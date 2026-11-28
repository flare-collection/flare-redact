using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Xunit;

namespace FlareRedact.Tests
{
    /// <summary>
    /// A value under a sensitive key is masked whatever its type (SPEC §9): numbers, byte arrays,
    /// GUIDs and every string or number inside a dictionary or sequence at any depth. Booleans,
    /// dates and null are kept.
    /// </summary>
    public class SensitiveValuesTests
    {
        private static Dictionary<string, object?> Map(params object?[] pairs)
        {
            var output = new Dictionary<string, object?>(StringComparer.Ordinal);
            for (int i = 0; i < pairs.Length; i += 2) output[(string)pairs[i]!] = pairs[i + 1];
            return output;
        }

        [Fact]
        public void NumbersAndContainersUnderASensitiveKeyAreMasked()
        {
            var policy = Policy.Compile();
            var output = (Dictionary<string, object?>)policy.Redact(Map(
                "cvv", 123,
                "amount", 1000,
                "cookie", Map("name", "connect.sid", "value", "s%3A_SID_abc"),
                "password", new List<object?> { "hunter2", new object?[] { "letmein", 7.5 } },
                "credentials", Map("hash", "$argon2id$v=19$abc", "params", Map("cost", 12L), "rotated", true),
                "pin", new[] { 1234, 5678 },
                "hasPassword", true,
                "token", null))!;
            Assert.Equal("***", output["cvv"]);
            Assert.Equal(1000, output["amount"]);
            Assert.Equal(Map("name", "***", "value", "***"), output["cookie"]);
            var password = (List<object?>)output["password"]!;
            Assert.Equal("***", password[0]);
            Assert.Equal(new object?[] { "***", "***" }, (object?[])password[1]!);
            var credentials = (Dictionary<string, object?>)output["credentials"]!;
            Assert.Equal("***", credentials["hash"]);
            Assert.Equal(Map("cost", "***"), credentials["params"]);
            Assert.Equal(true, credentials["rotated"]);
            Assert.Equal(new List<object?> { "***", "***" }, output["pin"]);
            Assert.Equal(true, output["hasPassword"]);
            Assert.Null(output["token"]);
        }

        [Fact]
        public void BytesGuidsAndBigNumbersAreReplacedAsTheirText()
        {
            var hash = Policy.Compile(new RedactOptions { Mode = Mode.Hash, TransformSecret = "k" });
            var guid = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
            Assert.Equal(
                hash.Redact(Map("secret", "0102ff", "pin", "1234", "api_key", "0f8fad5b-d9cb-469f-a165-70867728950e")),
                hash.Redact(Map("secret", new byte[] { 1, 2, 255 }, "pin", new BigInteger(1234), "api_key", guid)));
            Assert.NotEqual("***", ((Dictionary<string, object?>)Policy.Compile().Redact(Map("data", new byte[] { 9 }))!)["data"]);
            var allowed = Policy.Compile(new RedactOptions { Allow = new List<string> { "1234" } });
            Assert.Equal(Map("pin", 1234), allowed.Redact(Map("pin", 1234)));
        }

        private sealed class Login
        {
            public override string ToString() => "Login { User = ada, Password = hunter2 }";
        }

        [Fact]
        public void ObjectsTheWalkerCannotOpenAreMaskedAsText()
        {
            var when = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc);
            var output = (Dictionary<string, object?>)Policy.Compile().Redact(Map(
                "credentials", new Login(), "token", when, "secret", new Uri("https://x.test/?k=hunter2"),
                "auth", new KeyValuePair<string, string>("u", "hunter2")))!;
            Assert.Equal("***", output["credentials"]);
            Assert.Equal(when, output["token"]);
            Assert.Equal("***", output["secret"]);
            Assert.Equal("***", output["auth"]);
            var policy = Policy.Compile(new RedactOptions { IncludeValues = true });
            Assert.Equal("Login { User = ada, Password = hunter2 }", policy.Scan(Map("credentials", new Login())).Single().Value);
        }

        [Fact]
        public void ASharedObjectKeepsItsCopiesApart()
        {
            var shared = Map("value", "abc");
            var output = (Dictionary<string, object?>)Policy.Compile().Redact(Map("a", shared, "cookie", shared, "b", shared))!;
            Assert.Equal(Map("value", "abc"), output["a"]);
            Assert.Equal(Map("value", "***"), output["cookie"]);
            Assert.Same(output["a"], output["b"]);
        }

        [Fact]
        public void FloatTextMatchesEcmaScript()
        {
            var cases = new (double, string)[]
            {
                (1.5, "1.5"), (0.1, "0.1"), (1e-7, "1e-7"), (1.2e-5, "0.000012"), (1e21, "1e+21"), (1.5e21, "1.5e+21"),
                (1e16, "10000000000000000"), (100.0, "100"), (123456789012345680000.0, "123456789012345680000"),
                (0.1 + 0.2, "0.30000000000000004"), (5e-324, "5e-324"), (-42.25, "-42.25"), (-0.0, "0"),
                (double.NaN, "NaN"), (double.NegativeInfinity, "-Infinity"), (2e-3, "0.002"),
            };
            foreach ((double value, string text) in cases) Assert.Equal(text, SensitiveValues.JsFloat(value, false));
            Assert.Equal("1.1", SensitiveValues.Text(1.1f));
            Assert.Equal("1234", SensitiveValues.Text(1234.000m));
            Assert.Equal("1.5", SensitiveValues.Text(1.50m));
        }

        [Fact]
        public void ScanReportsEveryValueInside()
        {
            var policy = Policy.Compile(new RedactOptions { IncludeValues = true });
            var found = policy.Scan(Map("cvv", 123, "cookie", Map("name", "sid", "secure", true), "ok", 1))
                .Select(f => f.Detector + " " + f.Path + " " + f.Value).ToList();
            Assert.Equal(new[] { "sensitive_key cvv 123", "sensitive_key cookie.name sid" }, found);
        }

        [Fact]
        public void AVaultMintsAndRestoresSensitiveValues()
        {
            var vault = Policy.Compile().CreateVault(VaultOptions.ReadablePlaceholders);
            object? output = vault.Redact(Map("otp", 482913, "cookie", Map("value", "abc")));
            var redacted = (Dictionary<string, object?>)output!;
            Assert.Equal("[SENSITIVE_KEY_1]", redacted["otp"]);
            Assert.Equal(Map("value", "[SENSITIVE_KEY_2]"), redacted["cookie"]);
            var restored = (Dictionary<string, object?>)vault.Restore(output)!;
            Assert.Equal("482913", restored["otp"]);
            Assert.Equal(Map("value", "abc"), restored["cookie"]);
        }
    }
}
