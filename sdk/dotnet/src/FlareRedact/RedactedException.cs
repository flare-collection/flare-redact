using System;

namespace FlareRedact
{
    /// <summary>
    /// A stand-in for an exception whose message, stack trace and <see cref="ToString"/> text have
    /// been redacted, for logging integrations: an exception message is a common way for a
    /// connection string or a token to reach a log. The original is not kept.
    /// </summary>
    public sealed class RedactedException : Exception
    {
        private readonly string _text;
        private readonly string? _stackTrace;

        /// <summary>Redact an exception with a policy.</summary>
        /// <remarks>
        /// When a text is over the policy's limits it is withheld rather than passed on unredacted.
        /// </remarks>
        public RedactedException(Exception original, Policy policy)
            : base(Safe(policy, (original ?? throw new ArgumentNullException(nameof(original))).Message))
        {
            OriginalType = original.GetType().FullName ?? original.GetType().Name;
            _text = Safe(policy, original.ToString());
            _stackTrace = original.StackTrace == null ? null : Safe(policy, original.StackTrace);
            HResult = original.HResult;
            Source = original.Source;
        }

        /// <summary>The text written in place of anything a configured limit stopped from being redacted.</summary>
        public const string Withheld = "[flare-redact: text withheld, redaction limit exceeded]";

        /// <summary>The full name of the original exception's type.</summary>
        public string OriginalType { get; }

        /// <inheritdoc />
        public override string? StackTrace => _stackTrace;

        /// <inheritdoc />
        public override string ToString() => _text;

        /// <summary>
        /// <paramref name="text"/> redacted, or <see cref="Withheld"/> when a limit was exceeded:
        /// a logger must neither throw nor pass the text on unredacted.
        /// </summary>
        public static string Safe(Policy policy, string text)
        {
            if (policy == null) throw new ArgumentNullException(nameof(policy));
            try
            {
                return policy.RedactString(text);
            }
            catch (RedactionLimitException)
            {
                return Withheld;
            }
        }
    }
}
