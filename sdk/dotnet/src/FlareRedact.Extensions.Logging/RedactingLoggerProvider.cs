using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace FlareRedact.Extensions.Logging
{
    /// <summary>
    /// Wraps a logger provider so every logger it creates redacts before writing: the formatted
    /// message, each structured value, the message template's literal text, scope state and,
    /// unless turned off, the exception.
    /// </summary>
    public sealed class RedactingLoggerProvider : ILoggerProvider, ISupportExternalScope
    {
        private readonly ILoggerProvider _inner;
        private readonly Policy _policy;
        private readonly bool _redactExceptions;

        /// <summary>A provider that redacts with <paramref name="policy"/> before <paramref name="inner"/> sees anything.</summary>
        public RedactingLoggerProvider(ILoggerProvider inner, Policy policy, bool redactExceptions = true)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _policy = policy ?? throw new ArgumentNullException(nameof(policy));
            _redactExceptions = redactExceptions;
        }

        /// <summary>The wrapped provider.</summary>
        public ILoggerProvider Inner => _inner;

        /// <inheritdoc />
        public ILogger CreateLogger(string categoryName) =>
            new RedactingLogger(_inner.CreateLogger(categoryName), _policy, _redactExceptions);

        /// <inheritdoc />
        public void SetScopeProvider(IExternalScopeProvider scopeProvider)
        {
            if (_inner is ISupportExternalScope external) external.SetScopeProvider(new RedactingScopeProvider(scopeProvider, _policy));
        }

        /// <inheritdoc />
        public void Dispose() => _inner.Dispose();
    }

    /// <summary>A logger that redacts before handing anything to the logger it wraps.</summary>
    public sealed class RedactingLogger : ILogger
    {
        private readonly ILogger _inner;
        private readonly Policy _policy;
        private readonly bool _redactExceptions;

        /// <summary>A logger that redacts with <paramref name="policy"/> before writing to <paramref name="inner"/>.</summary>
        public RedactingLogger(ILogger inner, Policy policy, bool redactExceptions = true)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _policy = policy ?? throw new ArgumentNullException(nameof(policy));
            _redactExceptions = redactExceptions;
        }

        /// <inheritdoc />
        public bool IsEnabled(LogLevel logLevel) => _inner.IsEnabled(logLevel);

        /// <inheritdoc />
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
            _inner.BeginScope(StateRedactor.RedactScope(state, _policy));

        /// <inheritdoc />
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!_inner.IsEnabled(logLevel)) return;
            if (formatter == null) throw new ArgumentNullException(nameof(formatter));
            IReadOnlyList<KeyValuePair<string, object?>> values = StateRedactor.RedactValues(state, _policy);
            // The formatter would write the raw values into the message, so a password logged as
            // {Password} would be in clear text there; render from the redacted values instead.
            string message = StateRedactor.Render(values)
                ?? RedactedException.Safe(_policy, formatter(state, exception) ?? "");
            Exception? error = exception;
            if (_redactExceptions && error != null && !(error is RedactedException)) error = new RedactedException(error, _policy);
            var redacted = new RedactedLogState(message, values);
            _inner.Log(logLevel, eventId, redacted, error, (s, _) => s.Message);
        }
    }

    /// <summary>
    /// The state a wrapped provider receives: the redacted values, as the structured key-value
    /// list <c>ILogger</c> state usually is, with the redacted message as its text.
    /// </summary>
    public sealed class RedactedLogState : IReadOnlyList<KeyValuePair<string, object?>>
    {
        private readonly IReadOnlyList<KeyValuePair<string, object?>> _values;

        internal RedactedLogState(string message, IReadOnlyList<KeyValuePair<string, object?>> values)
        {
            Message = message;
            _values = values;
        }

        /// <summary>The redacted, formatted message.</summary>
        public string Message { get; }

        /// <inheritdoc />
        public KeyValuePair<string, object?> this[int index] => _values[index];

        /// <inheritdoc />
        public int Count => _values.Count;

        /// <inheritdoc />
        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => _values.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        /// <inheritdoc />
        public override string ToString() => Message;
    }

    internal static class StateRedactor
    {
        internal const string OriginalFormat = "{OriginalFormat}";

        internal static IReadOnlyList<KeyValuePair<string, object?>> RedactValues<TState>(TState state, Policy policy)
        {
            if (!(state is IEnumerable<KeyValuePair<string, object?>> pairs)) return Array.Empty<KeyValuePair<string, object?>>();
            var output = new List<KeyValuePair<string, object?>>();
            foreach (KeyValuePair<string, object?> pair in pairs) output.Add(new KeyValuePair<string, object?>(pair.Key, RedactPair(pair, policy)));
            return output;
        }

        private static object? RedactPair(KeyValuePair<string, object?> pair, Policy policy)
        {
            switch (pair.Value)
            {
                case null:
                    return null;
                case string text when pair.Key == OriginalFormat:
                    return RedactTemplate(text, policy);
                case string text:
                    try
                    {
                        return policy.RedactField(pair.Key, text);
                    }
                    catch (RedactionLimitException)
                    {
                        return RedactedException.Withheld;
                    }
                default:
                    try
                    {
                        // Under a sensitive key everything is masked, numbers and nested
                        // values included, as it would be under that key in a dictionary.
                        object? redacted = policy.IsSensitiveKey(pair.Key)
                            ? ((IDictionary)policy.Redact(new Dictionary<string, object?>(StringComparer.Ordinal) { [pair.Key] = pair.Value })!)[pair.Key]
                            : policy.Redact(pair.Value);
                        if (!PrintedAsText(pair.Value, redacted)) return redacted;
                        // A Uri, a class with its own ToString, a struct: the walker
                        // returns it unchanged, but the message and most providers print
                        // its ToString, so that text is what gets redacted.
                        return policy.RedactField(pair.Key, Convert.ToString(pair.Value, CultureInfo.InvariantCulture) ?? "");
                    }
                    catch (FlareRedactException)
                    {
                        return RedactedException.Withheld;
                    }
            }
        }

        /// <summary>
        /// True when <paramref name="value"/> is printed with its <c>ToString</c> and the walker
        /// left it as it was: anything but numbers, dates, ids, booleans, characters, byte arrays
        /// and the maps, sequences and JSON values the walker rebuilds.
        /// </summary>
        internal static bool PrintedAsText(object value, object? redacted)
        {
            Type type = value.GetType();
            if (type.IsValueType) return !(value is IFormattable || value is bool || value is char);
            return ReferenceEquals(value, redacted) && !(value is byte[]);
        }

        internal static object RedactScope<TState>(TState state, Policy policy) where TState : notnull
        {
            switch (state)
            {
                case string text:
                    return RedactedException.Safe(policy, text);
                case IEnumerable<KeyValuePair<string, object?>> _:
                    return new RedactedLogState(RedactedException.Safe(policy, state.ToString() ?? ""), RedactValues(state, policy));
                default:
                    // BeginScope(new { Dsn = dsn }): providers print the scope's ToString.
                    return PrintedAsText(state, state)
                        ? RedactedException.Safe(policy, Convert.ToString(state, CultureInfo.InvariantCulture) ?? "")
                        : state;
            }
        }

        /// <summary>
        /// The message rendered as <c>Microsoft.Extensions.Logging</c> renders it, from redacted
        /// values and the redacted template: holes are filled by position, null is <c>(null)</c>, a
        /// sequence is its items joined by <c>", "</c>, and numbers use the invariant culture. Null
        /// when the state has no template or the template does not fit the values.
        /// </summary>
        internal static string? Render(IReadOnlyList<KeyValuePair<string, object?>> values)
        {
            string? template = null;
            var args = new List<object?>();
            foreach (KeyValuePair<string, object?> pair in values)
            {
                if (pair.Key == OriginalFormat) template = pair.Value as string;
                else args.Add(Argument(pair.Value));
            }
            if (template == null) return null;
            var composite = new StringBuilder(template.Length + 8);
            int hole = 0;
            int i = 0;
            while (i < template.Length)
            {
                char c = template[i];
                if ((c == '{' || c == '}') && i + 1 < template.Length && template[i + 1] == c)
                {
                    composite.Append(c).Append(c);
                    i += 2;
                    continue;
                }
                if (c == '{')
                {
                    int close = template.IndexOf('}', i + 1);
                    if (close < 0) return null;
                    string inside = template.Substring(i + 1, close - i - 1);
                    int suffix = inside.IndexOfAny(new[] { ',', ':' });
                    composite.Append('{').Append(hole++).Append(suffix < 0 ? "" : inside.Substring(suffix)).Append('}');
                    i = close + 1;
                    continue;
                }
                if (c == '}') return null;
                composite.Append(c);
                i++;
            }
            if (hole != args.Count) return null;
            try
            {
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, composite.ToString(), args.ToArray());
            }
            catch (FormatException)
            {
                return null;
            }
        }

        private static object Argument(object? value)
        {
            switch (value)
            {
                case null:
                    return "(null)";
                case string text:
                    return text;
                case IEnumerable items:
                {
                    var parts = new List<string>();
                    foreach (object? item in items) parts.Add(item == null ? "(null)" : Convert.ToString(item, System.Globalization.CultureInfo.InvariantCulture) ?? "");
                    return string.Join(", ", parts);
                }
                default:
                    return value;
            }
        }

        /// <summary>
        /// A message template with its literal text redacted and its holes (<c>{Name}</c>) left as
        /// written, so structured providers can still pair holes with values.
        /// </summary>
        internal static string RedactTemplate(string template, Policy policy)
        {
            var output = new StringBuilder(template.Length);
            var literal = new StringBuilder();
            int i = 0;
            while (i < template.Length)
            {
                char c = template[i];
                if ((c == '{' || c == '}') && i + 1 < template.Length && template[i + 1] == c)
                {
                    literal.Append(c).Append(c);
                    i += 2;
                    continue;
                }
                if (c == '{')
                {
                    int close = template.IndexOf('}', i + 1);
                    if (close > i)
                    {
                        Flush(output, literal, policy);
                        output.Append(template, i, close + 1 - i);
                        i = close + 1;
                        continue;
                    }
                }
                literal.Append(c);
                i++;
            }
            Flush(output, literal, policy);
            return output.ToString();
        }

        private static void Flush(StringBuilder output, StringBuilder literal, Policy policy)
        {
            if (literal.Length == 0) return;
            // Redact the text as it reads, then escape any brace a replacement brought in.
            string text = literal.ToString().Replace("{{", "{").Replace("}}", "}");
            string redacted = RedactedException.Safe(policy, text);
            output.Append(string.Equals(redacted, text, StringComparison.Ordinal)
                ? literal.ToString()
                : redacted.Replace("{", "{{").Replace("}", "}}"));
            literal.Clear();
        }
    }

    /// <summary>Redacts scope state on its way to providers that read scopes from the shared scope provider.</summary>
    internal sealed class RedactingScopeProvider : IExternalScopeProvider
    {
        private readonly IExternalScopeProvider _inner;
        private readonly Policy _policy;

        internal RedactingScopeProvider(IExternalScopeProvider inner, Policy policy)
        {
            _inner = inner;
            _policy = policy;
        }

        public void ForEachScope<TState>(Action<object?, TState> callback, TState state) =>
            _inner.ForEachScope((scope, s) => callback(scope == null ? null : StateRedactor.RedactScope(scope, _policy), s), state);

        public IDisposable Push(object? state) => _inner.Push(state);
    }
}
