using System;
using FlareRedact;
using FlareRedact.Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;

namespace Serilog
{
    /// <summary>Adds FlareRedact to a Serilog <see cref="LoggerConfiguration"/>.</summary>
    public static class FlareRedactLoggerConfigurationExtensions
    {
        /// <summary>
        /// Redact every event property. <paramref name="options"/> is a JSON document in the wire
        /// format shared by every FlareRedact engine, so it can come from <c>appsettings.json</c>;
        /// null means the defaults.
        /// </summary>
        public static LoggerConfiguration WithFlareRedact(this LoggerEnrichmentConfiguration enrich, string? options = null) =>
            WithFlareRedact(enrich, Policy.Compile(options == null ? null : RedactOptions.FromJson(options)));

        /// <summary>Redact every event property with a compiled policy.</summary>
        public static LoggerConfiguration WithFlareRedact(this LoggerEnrichmentConfiguration enrich, Policy policy)
        {
            if (enrich == null) throw new ArgumentNullException(nameof(enrich));
            return enrich.With(new RedactingEnricher(policy));
        }

        /// <summary>
        /// Write to the sinks configured in <paramref name="configure"/> through a redacting wrapper
        /// that covers properties, message template text and exceptions. <paramref name="options"/>
        /// is a JSON document in the shared wire format; null means the defaults.
        /// </summary>
        public static LoggerConfiguration FlareRedact(
            this LoggerSinkConfiguration writeTo,
            Action<LoggerSinkConfiguration> configure,
            string? options = null,
            bool redactExceptions = true,
            LogEventLevel restrictedToMinimumLevel = LevelAlias.Minimum,
            LoggingLevelSwitch? levelSwitch = null) =>
            FlareRedact(writeTo, configure, Policy.Compile(options == null ? null : RedactOptions.FromJson(options)),
                redactExceptions, restrictedToMinimumLevel, levelSwitch);

        /// <summary>Write to the sinks configured in <paramref name="configure"/> through a redacting wrapper.</summary>
        public static LoggerConfiguration FlareRedact(
            this LoggerSinkConfiguration writeTo,
            Action<LoggerSinkConfiguration> configure,
            Policy policy,
            bool redactExceptions = true,
            LogEventLevel restrictedToMinimumLevel = LevelAlias.Minimum,
            LoggingLevelSwitch? levelSwitch = null)
        {
            if (writeTo == null) throw new ArgumentNullException(nameof(writeTo));
            if (configure == null) throw new ArgumentNullException(nameof(configure));
            if (policy == null) throw new ArgumentNullException(nameof(policy));
            return LoggerSinkConfiguration.Wrap(writeTo, sink => new RedactingSink(sink, policy, redactExceptions),
                configure, restrictedToMinimumLevel, levelSwitch);
        }
    }
}
