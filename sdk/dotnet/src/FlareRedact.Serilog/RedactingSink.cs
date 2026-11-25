using System;
using Serilog.Core;
using Serilog.Events;

namespace FlareRedact.Serilog
{
    /// <summary>
    /// Wraps another sink and hands it a redacted copy of every event: properties, the literal
    /// text of the message template and, unless turned off, the exception.
    /// </summary>
    public sealed class RedactingSink : ILogEventSink, IDisposable
    {
        private readonly ILogEventSink _inner;
        private readonly Policy _policy;
        private readonly bool _redactExceptions;

        /// <summary>A sink that redacts with <paramref name="policy"/> before writing to <paramref name="inner"/>.</summary>
        public RedactingSink(ILogEventSink inner, Policy policy, bool redactExceptions = true)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _policy = policy ?? throw new ArgumentNullException(nameof(policy));
            _redactExceptions = redactExceptions;
        }

        /// <inheritdoc />
        public void Emit(LogEvent logEvent)
        {
            if (logEvent == null) throw new ArgumentNullException(nameof(logEvent));
            _inner.Emit(LogEventRedactor.Redact(logEvent, _policy, _redactExceptions));
        }

        /// <inheritdoc />
        public void Dispose() => (_inner as IDisposable)?.Dispose();
    }

    /// <summary>
    /// Redacts every property of an event in place. Enrichers cannot change the message template
    /// or the exception; use the wrapping sink (<c>WriteTo.FlareRedact(...)</c>) to cover those.
    /// </summary>
    public sealed class RedactingEnricher : ILogEventEnricher
    {
        private readonly Policy _policy;

        /// <summary>An enricher that redacts with <paramref name="policy"/>.</summary>
        public RedactingEnricher(Policy policy) => _policy = policy ?? throw new ArgumentNullException(nameof(policy));

        /// <inheritdoc />
        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            if (logEvent == null) throw new ArgumentNullException(nameof(logEvent));
            foreach (var property in new System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<string, LogEventPropertyValue>>(logEvent.Properties))
            {
                LogEventPropertyValue redacted = LogEventRedactor.RedactValue(property.Value, property.Key, _policy);
                if (!ReferenceEquals(redacted, property.Value)) logEvent.AddOrUpdateProperty(new LogEventProperty(property.Key, redacted));
            }
        }
    }
}
