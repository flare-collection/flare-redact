using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Serilog.Events;
using Serilog.Parsing;

namespace FlareRedact.Serilog
{
    /// <summary>Redacts the parts of a Serilog event that can carry a secret.</summary>
    internal static class LogEventRedactor
    {
        private static readonly MessageTemplateParser Parser = new MessageTemplateParser();

        internal static LogEvent Redact(LogEvent logEvent, Policy policy, bool redactExceptions)
        {
            MessageTemplate template = RedactTemplate(logEvent.MessageTemplate, policy);
            IEnumerable<LogEventProperty> properties = logEvent.Properties
                .Select(p => new LogEventProperty(p.Key, RedactValue(p.Value, p.Key, policy)));
            Exception? exception = logEvent.Exception;
            if (redactExceptions && exception != null && !(exception is RedactedException))
            {
                exception = new RedactedException(exception, policy);
            }
            return new LogEvent(logEvent.Timestamp, logEvent.Level, exception, template, properties,
                logEvent.TraceId ?? default, logEvent.SpanId ?? default);
        }

        /// <summary>
        /// The template with its literal text redacted and its holes left as written, so a value
        /// concatenated into the template (<c>"token " + token</c>) is caught too.
        /// </summary>
        internal static MessageTemplate RedactTemplate(MessageTemplate template, Policy policy)
        {
            var text = new StringBuilder(template.Text.Length);
            bool changed = false;
            foreach (MessageTemplateToken token in template.Tokens)
            {
                if (token is TextToken literal)
                {
                    string redacted = RedactedException.Safe(policy, literal.Text);
                    changed |= !string.Equals(redacted, literal.Text, StringComparison.Ordinal);
                    text.Append(redacted.Replace("{", "{{").Replace("}", "}}"));
                }
                else
                {
                    text.Append(token.ToString());
                }
            }
            return changed ? Parser.Parse(text.ToString()) : template;
        }

        internal static LogEventPropertyValue RedactValue(LogEventPropertyValue value, string? key, Policy policy) =>
            RedactValue(value, key, policy, null);

        /// <summary>
        /// <paramref name="under"/> is the sensitive key the value sits beneath, or null. Beneath
        /// one, every scalar is masked whole, whatever its depth (SPEC §9).
        /// </summary>
        private static LogEventPropertyValue RedactValue(LogEventPropertyValue value, string? key, Policy policy, string? under)
        {
            if (under == null && key != null && policy.IsSensitiveKey(key)) under = key;
            switch (value)
            {
                case ScalarValue scalar when under != null && scalar.Value != null:
                    return new ScalarValue(Masked(policy, under, scalar.Value));
                case ScalarValue scalar when scalar.Value is string text:
                    return new ScalarValue(key == null ? RedactedException.Safe(policy, text) : SafeField(policy, key, text));
                case ScalarValue scalar when scalar.Value != null && PrintedAsText(scalar.Value):
                {
                    // Serilog keeps a Uri (and anything a policy turns into a scalar) as the
                    // object, then renders it with ToString: redact that text.
                    string text = Convert.ToString(scalar.Value, CultureInfo.InvariantCulture) ?? "";
                    return new ScalarValue(key == null ? RedactedException.Safe(policy, text) : SafeField(policy, key, text));
                }
                case SequenceValue sequence:
                    return new SequenceValue(sequence.Elements.Select(e => RedactValue(e, null, policy, under)));
                case StructureValue structure:
                    return new StructureValue(
                        structure.Properties.Select(p => new LogEventProperty(p.Name, RedactValue(p.Value, p.Name, policy, under))),
                        structure.TypeTag);
                case DictionaryValue dictionary:
                    return new DictionaryValue(dictionary.Elements.Select(e => new KeyValuePair<ScalarValue, LogEventPropertyValue>(
                        e.Key, RedactValue(e.Value, e.Key.Value as string, policy, under))));
                default:
                    return value;
            }
        }

        /// <summary>
        /// True for a scalar printed with its <c>ToString</c>: anything but numbers, dates, ids,
        /// booleans, characters and byte arrays.
        /// </summary>
        private static bool PrintedAsText(object value) =>
            value.GetType().IsValueType ? !(value is IFormattable || value is bool || value is char) : !(value is byte[]);

        /// <summary>
        /// A scalar beneath a sensitive key, masked as it would be under that key in a dictionary:
        /// text, numbers, GUIDs and byte arrays whole; booleans and dates kept. A value Serilog
        /// prints with its <c>ToString</c> is masked as that text.
        /// </summary>
        private static object? Masked(Policy policy, string key, object value)
        {
            object input = value is string || !PrintedAsText(value)
                ? value
                : Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
            try
            {
                var field = new Dictionary<string, object?>(StringComparer.Ordinal) { [key] = input };
                return ((IDictionary)policy.Redact(field)!)[key];
            }
            catch (RedactionLimitException)
            {
                return RedactedException.Withheld;
            }
        }

        private static string SafeField(Policy policy, string key, string text)
        {
            try
            {
                return policy.RedactField(key, text);
            }
            catch (RedactionLimitException)
            {
                return RedactedException.Withheld;
            }
        }
    }
}
