using System;
using System.Collections.Generic;
using System.Linq;

namespace FlareRedact
{
    /// <summary>
    /// One-call entry points over a shared default <see cref="Policy"/>. For anything configured,
    /// compile a policy once with <see cref="Policy.Compile"/> and reuse it.
    /// </summary>
    public static class Redactor
    {
        /// <summary>The library version.</summary>
        public const string Version = "1.12.1";

        private static readonly Lazy<Policy> Defaults = new Lazy<Policy>(() => Policy.Compile());

        /// <summary>The shared policy with the default options.</summary>
        public static Policy DefaultPolicy => Defaults.Value;

        /// <summary>Redact one string with the default policy, or with <paramref name="options"/>.</summary>
        public static string RedactString(string text, RedactOptions? options = null) =>
            (options == null ? DefaultPolicy : Policy.Compile(options)).RedactString(text);

        /// <summary>Redact every string in a structured value with the default policy, or with <paramref name="options"/>.</summary>
        public static object? Redact(object? value, RedactOptions? options = null) =>
            (options == null ? DefaultPolicy : Policy.Compile(options)).Redact(value);

        /// <summary>Redact a JSON document with the default policy, or with <paramref name="options"/>.</summary>
        public static string RedactJson(string json, RedactOptions? options = null) =>
            (options == null ? DefaultPolicy : Policy.Compile(options)).RedactJson(json);

        /// <summary>List what would be redacted, and why.</summary>
        public static IReadOnlyList<Finding> Scan(object? value, RedactOptions? options = null) =>
            (options == null ? DefaultPolicy : Policy.Compile(options)).Scan(value);

        /// <summary>Whether nothing in a value would be redacted by the default policy.</summary>
        public static bool IsClean(object? value) => DefaultPolicy.IsClean(value);

        /// <summary>Counts of findings by detector and by risk, with no values.</summary>
        public static Summary Summarize(object? value) => DefaultPolicy.Summarize(value);

        /// <summary>Put originals back into a value, given placeholder to original pairs.</summary>
        public static object? Restore(object? value, IEnumerable<KeyValuePair<string, string>> entries) =>
            new Policy.Walker(Restorers.JsonAware(entries.ToList()), null).Walk(value, 0);
    }
}
