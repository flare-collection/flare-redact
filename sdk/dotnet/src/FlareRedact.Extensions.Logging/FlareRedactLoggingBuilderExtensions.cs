using System;
using System.Collections.Generic;
using System.Linq;
using FlareRedact;
using FlareRedact.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.Logging
{
    /// <summary>Adds FlareRedact to a Microsoft.Extensions.Logging pipeline.</summary>
    public static class FlareRedactLoggingBuilderExtensions
    {
        /// <summary>
        /// Wrap every logger provider registered so far, so each one receives redacted messages,
        /// state, scopes and exceptions. Call it after adding your providers: a provider added
        /// later is not wrapped. <paramref name="options"/> null means the defaults.
        /// </summary>
        public static ILoggingBuilder AddFlareRedact(this ILoggingBuilder builder, RedactOptions? options = null, bool redactExceptions = true) =>
            AddFlareRedact(builder, Policy.Compile(options), redactExceptions);

        /// <summary>
        /// <see cref="AddFlareRedact(ILoggingBuilder, RedactOptions?, bool)"/> with options as a JSON
        /// document in the wire format shared by every FlareRedact engine.
        /// </summary>
        public static ILoggingBuilder AddFlareRedact(this ILoggingBuilder builder, string options, bool redactExceptions = true) =>
            AddFlareRedact(builder, Policy.Compile(RedactOptions.FromJson(options)), redactExceptions);

        /// <summary>Wrap every logger provider registered so far with a compiled policy.</summary>
        public static ILoggingBuilder AddFlareRedact(this ILoggingBuilder builder, Policy policy, bool redactExceptions = true)
        {
            if (builder == null) throw new ArgumentNullException(nameof(builder));
            if (policy == null) throw new ArgumentNullException(nameof(policy));
            IServiceCollection services = builder.Services;
            List<ServiceDescriptor> providers = services.Where(d => d.ServiceType == typeof(ILoggerProvider) && !d.IsKeyedService).ToList();
            foreach (ServiceDescriptor original in providers)
            {
                int index = services.IndexOf(original);
                services[index] = ServiceDescriptor.Describe(typeof(ILoggerProvider),
                    sp => Wrap(sp, original, policy, redactExceptions), original.Lifetime);
            }
            return builder;
        }

        private static ILoggerProvider Wrap(IServiceProvider services, ServiceDescriptor original, Policy policy, bool redactExceptions)
        {
            object inner = original.ImplementationInstance
                ?? original.ImplementationFactory?.Invoke(services)
                ?? ActivatorUtilities.CreateInstance(services, original.ImplementationType!);
            return inner is RedactingLoggerProvider already
                ? already
                : new RedactingLoggerProvider((ILoggerProvider)inner, policy, redactExceptions);
        }
    }
}
