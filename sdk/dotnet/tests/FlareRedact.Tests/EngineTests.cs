using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Xunit;

namespace FlareRedact.Tests
{
    public class EngineTests
    {
        private const string Smile = "\U0001F600";

        private static bool LibraryIsNet8 =>
            typeof(Policy).Assembly.GetCustomAttribute<TargetFrameworkAttribute>()?.FrameworkName.StartsWith(".NETCoreApp") == true;

        private static string Repeat(string s, int n) => new StringBuilder(s.Length * n).Insert(0, s, n).ToString();

        private static Pack MakePack(string detector) =>
            Pack.Load("{\"spec\":\"FRS-1\",\"id\":\"test\",\"version\":\"1\",\"detectors\":[" + detector + "]}");

        private static string MakeDetector(string pattern, string flags = "") =>
            "{\"id\":\"t\",\"label\":\"T\",\"why\":\"w\",\"pattern\":" + Json.Stringify(pattern)
            + (flags.Length > 0 ? ",\"flags\":\"" + flags + "\"" : "")
            + ",\"mask\":{\"type\":\"fixed\"},\"default\":true,\"risk\":\"high\",\"confidence\":0.9}";

        private static Policy WithPattern(string pattern, string flags = "") =>
            Policy.Compile(new RedactOptions { Pack = MakePack(MakeDetector(pattern, flags)) });

        [Fact]
        public void MasksTheDefaults()
        {
            string output = Redactor.RedactString("contact ada@example.com now");
            Assert.DoesNotContain("ada@example.com", output);
            Assert.StartsWith("contact ", output);
            Assert.EndsWith(" now", output);
            Assert.True(Redactor.IsClean("the quick brown fox"));
            Assert.False(Redactor.IsClean("AKIAIOSFODNN7EXAMPLE"));
        }

        [Fact]
        public void InputLimitCountsUtf16Units()
        {
            string text = "üüüü" + Smile + Smile;
            Assert.Equal(8, text.Length);
            Assert.Equal(text, Policy.Compile(new RedactOptions { MaxInputLength = 8 }).RedactString(text));
            Policy over = Policy.Compile(new RedactOptions { MaxInputLength = 7 });
            Assert.Throws<RedactionLimitException>(() => over.RedactString(text));
        }

        [Fact]
        public void TooManyFindingsFailClosed()
        {
            Policy policy = Policy.Compile(new RedactOptions { MaxFindings = 3 });
            Assert.Throws<RedactionLimitException>(() => policy.RedactString(Repeat("ada@example.com ", 4)));
        }

        [Fact]
        public void DeepRepetitionDoesNotExhaustTheStack()
        {
            // .NET's regex engines keep backtracking state on the heap, so a long run that
            // overflows a recursive matcher's stack is just a long run here.
            Policy policy = WithPattern("(?:a|b)+x");
            string text = Repeat("ab", 1_000_000) + "x";
            Assert.Equal("***", policy.RedactString(text));
        }

        [Fact]
        public void KeyedModesNeedASecret()
        {
            Assert.Throws<FlareRedactException>(() => Policy.Compile(new RedactOptions { Mode = Mode.Hash }));
            Policy hash = Policy.Compile(new RedactOptions { Mode = Mode.Hash, TransformSecret = "k" });
            string output = hash.RedactString("mail ada@example.com");
            Assert.Matches("^mail email_[0-9a-f]{32}$", output);
            Assert.Equal(output, hash.RedactString("mail ada@example.com"));
        }

        [Fact]
        public void LabelAndFixedMasks()
        {
            Assert.Equal("mail [REDACTED:email]", Policy.Compile(new RedactOptions { Mode = Mode.Label }).RedactString("mail ada@example.com"));
            Assert.Equal("mail #", Policy.Compile(new RedactOptions { Mask = "#" }).RedactString("mail ada@example.com"));
            Policy custom = Policy.Compile(new RedactOptions { MaskFunction = (value, d) => "<" + d.Id + ":" + value.Length + ">" });
            Assert.Equal("mail <email:15>", custom.RedactString("mail ada@example.com"));
        }

        [Fact]
        public void ZeroWidthSplicesAreCovered()
        {
            string output = Redactor.RedactString("key AKIA​IOSFODNN7EXAMPLE end");
            Assert.DoesNotContain("IOSFODNN7", output);
            Assert.StartsWith("key ", output);
            Assert.EndsWith(" end", output);
        }

        [Fact]
        public void TermsRespectUnicodeWordBoundaries()
        {
            Policy policy = Policy.Compile(new RedactOptions
            {
                Terms = { "Bluebird", new Term("istanbul", "[CITY]"), "café" },
            });
            Assert.Equal("*** and Bluebirds", policy.RedactString("Bluebird and Bluebirds"));
            Assert.Equal("[CITY]!", policy.RedactString("İSTANBUL!"));
            // A combining mark or an astral letter next to the term makes it part of a word.
            string astral = char.ConvertFromUtf32(0x10400);
            Assert.Equal("bluebird́", policy.RedactString("bluebird́"));
            Assert.Equal(astral + "bluebird", policy.RedactString(astral + "bluebird"));
            Assert.Equal(Smile + "***", policy.RedactString(Smile + "bluebird"));
        }

        [Fact]
        public void TermsCanBeCaseSensitive()
        {
            Policy policy = Policy.Compile(new RedactOptions { Terms = { "Atlas" }, TermsCaseSensitive = true });
            Assert.Equal("*** atlas", policy.RedactString("Atlas atlas"));
        }

        [Fact]
        public void CaseFoldingUsesTheBundledTable()
        {
            Assert.Contains(0x212A, CaseFolding.Orbit('k')!);
            Assert.Equal(new[] { 'I', 'i', 0x130, 0x131 }, CaseFolding.Orbit(0x131));
            Assert.NotNull(CaseFolding.Orbit(0x1C89));
            Assert.Null(CaseFolding.Orbit('1'));
            Assert.Equal("*** ***", WithPattern("secret[0-9]", "i").RedactString("SECRET1 ſecret2"));
        }

        [Fact]
        public void PatternsMoveByCodePoint()
        {
            // An astral code point is one character to every pattern, as with JavaScript's u flag.
            Assert.Equal(Smile + "a", WithPattern(".{3}").RedactString(Smile + "a"));
            Assert.Equal("***", WithPattern(".{3}").RedactString(Smile + "ab"));
            Assert.Equal("***", WithPattern("{{ANY}}x").RedactString(Smile + "x"));
            Assert.Equal("a ***", WithPattern("[^a ]x").RedactString("a " + Smile + "x"));
            Assert.Equal("q ***", WithPattern("[\U0001F600-\U0001F64F]+").RedactString("q \U0001F600\U0001F64F"));
            Assert.Equal("***", WithPattern("{{L}}{2}").RedactString(char.ConvertFromUtf32(0x10400) + "a"));
            // A lone surrogate in the text is one character too, and a match never starts inside a pair.
            Assert.Equal("*** z", WithPattern("[^ ]x").RedactString("\uD83Dx z"));
            Assert.Equal(Smile, WithPattern("\uDE00").RedactString(Smile));
            Assert.Equal("***!", WithPattern("[\uD800-\uDBFF]").RedactString("\uD83D!"));
            Assert.Equal(Smile, WithPattern("[\uD800-\uDBFF]").RedactString(Smile));
        }

        [Fact]
        public void TranslatedPatternsKeepJavaScriptMeaning()
        {
            // $ is the end of input, not "before a final newline".
            Regex end = new Regex(PatternTranslator.Translate("a$", false));
            Assert.Matches(end, "a");
            Assert.DoesNotMatch(end, "a\n");
            // \d and \w are ASCII, \s is JavaScript's whitespace.
            Assert.DoesNotMatch(new Regex("^" + PatternTranslator.Translate("\\d", false) + "$"), "٣");
            Assert.DoesNotMatch(new Regex("^" + PatternTranslator.Translate("\\w", false) + "$"), "é");
            Assert.Matches(new Regex(PatternTranslator.Translate("\\s", false)), "﻿");
            Assert.DoesNotMatch(new Regex(PatternTranslator.Translate("\\s", false)), "\u0085");
            // Under /iu, \w takes in the long s and the Kelvin sign, and \W leaves them out.
            Assert.Matches(new Regex(PatternTranslator.Translate("\\w", true)), "K");
            Assert.DoesNotMatch(new Regex(PatternTranslator.Translate("[\\W]", true)), "ſ");
            Assert.DoesNotMatch(new Regex(PatternTranslator.Translate("\\W", true)), "s");
            Assert.Throws<ArgumentException>(() => PatternTranslator.Translate("[ab", false));
        }

        [Fact]
        public void SensitiveKeysAreNormalised()
        {
            var input = new Dictionary<string, object?>
            {
                ["PASSWORD"] = "hunter2",
                ["Şifrə"] = "x1",
                ["Passwort"] = "x2",
                ["note"] = "fine",
            };
            var output = (IDictionary<string, object?>)Redactor.Redact(input)!;
            Assert.Equal("***", output["PASSWORD"]);
            Assert.Equal("***", output["Şifrə"]);
            Assert.Equal("***", output["Passwort"]);
            Assert.Equal("fine", output["note"]);

            var custom = new Dictionary<string, object?> { ["INTERNAL_ID"] = "42", ["password"] = "kept" };
            var named = (IDictionary<string, object?>)Policy.Compile(new RedactOptions { KeyNames = new[] { "internal_id" } }).Redact(custom)!;
            Assert.Equal("***", named["INTERNAL_ID"]);
            Assert.Equal("kept", named["password"]);
            var none = (IDictionary<string, object?>)Policy.Compile(new RedactOptions { KeyNames = new List<string>() }).Redact(custom)!;
            Assert.Equal("kept", none["password"]);
        }

        [Fact]
        public void ScanReportsPathsAndPositions()
        {
            var input = new Dictionary<string, object?>
            {
                ["user"] = new Dictionary<string, object?> { ["email"] = "x ada@example.com", ["password"] = "hunter2" },
                ["items"] = new List<object?> { "a", "line one\nmail grace@example.org" },
            };
            IReadOnlyList<Finding> findings = Policy.Compile(new RedactOptions { IncludeValues = true }).Scan(input);
            Assert.Equal(3, findings.Count);
            Assert.Equal("user.email", findings[0].Path);
            Assert.Equal(2, findings[0].Start);
            Assert.Equal("ada@example.com", findings[0].Value);
            Assert.Equal("user.password", findings[1].Path);
            Assert.Equal(-1, findings[1].Start);
            Assert.Equal("sensitive_key", findings[1].Detector);
            Assert.Equal("items[1]", findings[2].Path);
            Assert.Equal(2, findings[2].Line);
            Assert.Equal(6, findings[2].Column);
            Assert.Null(Redactor.Scan(input)[0].Value);
            Assert.Null(Redactor.Scan("ada@example.com")[0].Path);
            Summary summary = Redactor.Summarize(input);
            Assert.Equal(3, summary.Total);
            Assert.Equal(2, summary.ByDetector["email"]);
            Assert.Equal(3, summary.ByRisk.Values.Sum());
        }

        [Fact]
        public void StructuredValuesKeepTheirShapeAndCycles()
        {
            var list = new List<object?> { "ada@example.com" };
            list.Add(list);
            var node = new Dictionary<string, object?>
            {
                ["list"] = list,
                ["n"] = 42,
                ["arr"] = new[] { "grace@example.org" },
                ["ids"] = new Dictionary<int, object?> { [7] = "ada@example.com" },
            };
            var output = (IDictionary<string, object?>)Redactor.Redact(node)!;
            var outList = (List<object?>)output["list"]!;
            Assert.DoesNotContain("ada@", (string)outList[0]!);
            Assert.Same(outList, outList[1]);
            Assert.Equal(42, output["n"]);
            Assert.IsType<string[]>(output["arr"]);
            Assert.DoesNotContain("grace@", ((string[])output["arr"]!)[0]);
            var ids = (Dictionary<object, object?>)output["ids"]!;
            Assert.DoesNotContain("ada@", (string)ids[7]!);
            Assert.Single(Redactor.Scan(list));
            // Your own classes are not walked: serialise them and use RedactJson.
            Assert.Empty(Redactor.Scan(new { Email = "ada@example.com" }));
        }

        [Fact]
        public void TooDeepNestingIsRefused()
        {
            object? value = "x";
            for (int i = 0; i < 1100; i++) value = new List<object?> { value };
            Assert.Throws<FlareRedactException>(() => Redactor.Redact(value));
            Assert.Throws<FlareRedactException>(() => Redactor.Scan(value));
        }

        [Fact]
        public void RedactJsonRoundTrips()
        {
            string output = Redactor.DefaultPolicy.RedactJson("{\"to\":\"ada@example.com\",\"password\":\"x\",\"n\":1.5}");
            var parsed = (IDictionary<string, object?>)Json.Parse(output)!;
            Assert.Equal("***", parsed["password"]);
            Assert.Equal(1.5, parsed["n"]);
            Assert.DoesNotContain("ada@example.com", output);
            Assert.Throws<FormatException>(() => Redactor.RedactJson("{nope"));
        }

        [Fact]
        public void SystemTextJsonValuesAreRedactedOnNet8()
        {
            if (!LibraryIsNet8) return;
            JsonNode node = JsonNode.Parse("{\"user\":{\"email\":\"ada@example.com\",\"password\":\"hunter2\"},\"n\":3}")!;
            var redacted = Assert.IsAssignableFrom<JsonObject>(Redactor.Redact(node));
            Assert.Equal("***", (string?)redacted["user"]!["password"]);
            Assert.DoesNotContain("ada@", (string?)redacted["user"]!["email"]);
            Assert.Equal(3, (int)redacted["n"]!);
            Assert.Equal("ada@example.com", (string?)node["user"]!["email"]);
            Assert.Equal(2, Redactor.Scan(node).Count);

            using JsonDocument document = JsonDocument.Parse("[\"mail ada@example.com\"]");
            var element = Assert.IsType<JsonElement>(Redactor.Redact(document.RootElement));
            Assert.DoesNotContain("ada@", element[0].GetString());
        }

        [Fact]
        public void VaultRoundTripsWithOpaquePlaceholders()
        {
            Vault vault = Vault.Create();
            string redacted = vault.RedactString("mail ada@example.com or ada@example.com");
            Assert.Matches(@"^mail \[FR_EMAIL_[0-9a-f]{24}] or \[FR_EMAIL_[0-9a-f]{24}]$", redacted);
            Assert.Equal(1, vault.Count);
            Assert.Equal("mail ada@example.com or ada@example.com", vault.RestoreString(redacted));
        }

        [Fact]
        public void VaultRefusesDuplicatePlaceholders()
        {
            Vault vault = Vault.Create(null, VaultOptions.CustomPlaceholders((id, n) => "[X]"));
            Assert.Throws<FlareRedactException>(() => vault.RedactString("ada@example.com grace@example.org"));
        }

        [Fact]
        public void RestoringIntoJsonEscapesOriginals()
        {
            Vault vault = Vault.Create(new RedactOptions { Terms = { "Q\"uo" } }, VaultOptions.ReadablePlaceholders);
            Assert.Equal("say [CUSTOM_TERM_1]", vault.RedactString("say Q\"uo"));
            Assert.Equal("[\"Q\\\"uo\", 1]", vault.RestoreString("[\"[CUSTOM_TERM_1]\", 1]"));
            Assert.Equal("said Q\"uo", vault.RestoreString("said [CUSTOM_TERM_1]"));
            Assert.True(Restorers.IsJsonDocument(" {\"a\":1}"));
            Assert.False(Restorers.IsJsonDocument("{ not json"));
            var map = (IDictionary<string, object?>)Redactor.Restore(new Dictionary<string, object?> { ["a"] = "[P]" },
                new[] { new KeyValuePair<string, string>("[P]", "x") })!;
            Assert.Equal("x", map["a"]);
        }

        [Fact]
        public void StreamRestorerHandlesSplitPlaceholders()
        {
            var session = new Session(null, VaultOptions.ReadablePlaceholders);
            Assert.Equal("write to [EMAIL_1]", session.RedactString("write to ada@example.com"));
            StreamRestorer stream = session.Stream();
            var output = new StringBuilder();
            foreach (string chunk in new[] { "Sure, [EM", "AIL", "_1] is", " set [EMA" }) output.Append(stream.Push(chunk));
            output.Append(stream.Flush());
            Assert.Equal("Sure, ada@example.com is set [EMA", output.ToString());
            session.Reset();
            Assert.Equal(0, session.Vault.Count);
        }

        [Fact]
        public void VaultIsSafeAcrossThreads()
        {
            Vault vault = Vault.Create(null, VaultOptions.ReadablePlaceholders);
            System.Threading.Tasks.Parallel.For(0, 200, i => vault.RedactString("user" + (i % 20) + "@example.com"));
            Assert.Equal(20, vault.Count);
            Assert.Equal(20, vault.Entries.Select(e => e.Key).Distinct().Count());
        }

        [Fact]
        public void WireOptionsRoundTrip()
        {
            RedactOptions options = RedactOptions.FromJson("{\"enable\":[\"phone\"],\"mode\":\"label\",\"redactKeys\":[\"a\"],"
                + "\"terms\":{\"Atlas\":\"[P]\",\"Orion\":\"[Q]\"},\"minConfidence\":0.5,\"limits\":{\"maxFindings\":10}}");
            Assert.Equal(Mode.Label, options.Mode);
            Assert.Equal(10, options.MaxFindings);
            Assert.Equal(new[] { "Atlas", "Orion" }, options.Terms.Select(t => t.Text));
            Assert.Equal(options.ToJson(), RedactOptions.FromJson(options.ToJson()).ToJson());
            Assert.Throws<ArgumentException>(() => RedactOptions.FromJson("{\"nope\":1}"));
            Assert.Throws<ArgumentException>(() => RedactOptions.FromJson("{\"only\":\"email\"}"));
            Assert.Throws<ArgumentException>(() => RedactOptions.FromJson("{\"mode\":\"shout\"}"));
        }

        [Fact]
        public void PolicySnapshotsItsOptions()
        {
            var options = new RedactOptions { Mode = Mode.Label };
            Policy policy = Policy.Compile(options);
            options.Mode = Mode.Mask;
            options.Terms.Add("Atlas");
            Assert.Equal("[REDACTED:email] Atlas", policy.RedactString("ada@example.com Atlas"));
        }

        [Fact]
        public void PackLoadingIsStrict()
        {
            Assert.Throws<PackException>(() => MakePack(MakeDetector("(?=a)b")));
            Assert.Throws<PackException>(() => MakePack(MakeDetector("\\d+")));
            Assert.Throws<PackException>(() => MakePack(MakeDetector("a*")));
            Assert.Throws<PackException>(() => MakePack(MakeDetector("^a")));
            Assert.Throws<PackException>(() => MakePack(MakeDetector("[a")));
            Assert.Throws<PackException>(() => MakePack(MakeDetector("(a")));
            Assert.Throws<PackException>(() => MakePack(
                "{\"id\":\"t\",\"label\":\"T\",\"why\":\"w\",\"pattern\":\"a\",\"validators\":[{\"name\":\"nope\"}],"
                + "\"mask\":{\"type\":\"fixed\"},\"default\":true,\"risk\":\"high\",\"confidence\":0.9}"));
            Assert.Throws<PackException>(() => Pack.Load("{\"spec\":\"FRS-2\",\"detectors\":[]}"));
            Assert.Throws<PackException>(() => Pack.Load("not json"));
            Assert.Equal(145, Pack.Core.Detectors.Count);
            Assert.NotNull(Pack.Core.GetDetector("email"));
            Assert.NotNull(Pack.Core.Model);
        }

        [Fact]
        public void KeywordsCoverTheSupportedLanguages()
        {
            Assert.True(Keywords.IsSensitiveKeyName("API-KEY"));
            Assert.True(Keywords.IsSensitiveKeyName("ΚΩΔΙΚΌΣ"));
            Assert.True(Keywords.IsSensitiveKeyName("ŞİFRE"));
            Assert.False(Keywords.IsSensitiveKeyName("username"));
            Assert.Equal(Keywords.SecretKeywords.OrderBy(k => k, StringComparer.Ordinal), Keywords.SecretKeywords);
        }

        [Fact]
        public void KeyedTransformsMatchTheOtherEngines()
        {
            // Lone surrogates are encoded as U+FFFD, as JavaScript's TextEncoder does.
            Assert.Equal(Transforms.HmacFingerprint("k", "�", 8), Transforms.HmacFingerprint("k", "\uD800", 8));
            Assert.Equal(16, Transforms.DeriveBytes("k", "ctx", 16).Length);
            Assert.Equal(70, Transforms.DeriveBytes("k", "ctx", 70).Length);
            string card = Transforms.Surrogate("4242 4242 4242 4242", "credit_card", "k");
            Assert.True(Checksums.Luhn(card, 12, 19), card);
            Assert.Matches("^user_[0-9a-f]{12}@example.invalid$", Transforms.Surrogate("ada@example.com", "email", "k"));
            Assert.Throws<FlareRedactException>(() => Transforms.Pseudonymize("x", ""));
        }
    }
}
