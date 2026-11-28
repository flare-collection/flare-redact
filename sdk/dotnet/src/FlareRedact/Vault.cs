using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace FlareRedact
{
    /// <summary>How a <see cref="Vault"/> mints placeholders.</summary>
    /// <remarks>
    /// Placeholders are opaque by default: <c>[FR_EMAIL_&lt;24 random hex digits&gt;]</c>, so the
    /// text that leaves your process does not also disclose how many distinct people or secrets it
    /// involves. Readable placeholders (<c>[EMAIL_1]</c>) are predictable; use them only for
    /// trusted local debugging.
    /// </remarks>
    public sealed class VaultOptions
    {
        private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

        internal readonly Func<string, int, string> Placeholder;

        private VaultOptions(Func<string, int, string> placeholder) => Placeholder = placeholder;

        /// <summary>Opaque placeholders, the default.</summary>
        public static VaultOptions Default { get; } = new VaultOptions(Opaque);

        /// <summary>Opaque placeholders: <c>[FR_&lt;ID&gt;_&lt;24 hex digits&gt;]</c> from a CSPRNG.</summary>
        public static VaultOptions OpaquePlaceholders => Default;

        /// <summary>Counted placeholders such as <c>[EMAIL_1]</c>; predictable, local debugging only.</summary>
        public static VaultOptions ReadablePlaceholders { get; } = new VaultOptions(Readable);

        /// <summary>
        /// Your own placeholder format. It receives the detector id and a per-detector count
        /// starting at 1, and must never return the same token for two different values: the vault
        /// refuses a duplicate rather than restore the wrong secret.
        /// </summary>
        public static VaultOptions CustomPlaceholders(Func<string, int, string> format) =>
            new VaultOptions(format ?? throw new ArgumentNullException(nameof(format)));

        private static string Opaque(string detectorId, int index)
        {
            var bytes = new byte[12];
            lock (Random) Random.GetBytes(bytes);
            return "[FR_" + detectorId.ToUpperInvariant() + "_" + Transforms.Hex(bytes, bytes.Length) + "]";
        }

        private static string Readable(string detectorId, int index) =>
            "[" + detectorId.ToUpperInvariant() + "_" + index.ToString(CultureInfo.InvariantCulture) + "]";
    }

    /// <summary>
    /// A reversible redactor. Each secret is swapped for a stable placeholder and the mapping is
    /// remembered, so you can send the redacted text to a model and put the originals back into
    /// its answer. The same value always maps to the same placeholder within one vault, so
    /// references survive the round trip.
    /// </summary>
    /// <remarks>
    /// A vault is thread-safe. It holds the originals in memory: keep it for one conversation (see
    /// <see cref="Session"/>) and let it go.
    /// </remarks>
    public sealed class Vault
    {
        private readonly object _lock = new object();
        private readonly VaultOptions _vaultOptions;
        private readonly Dictionary<string, string> _byValue = new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _byPlaceholder = new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly List<KeyValuePair<string, string>> _entries = new List<KeyValuePair<string, string>>();
        private readonly Dictionary<string, int> _counts = new Dictionary<string, int>(StringComparer.Ordinal);

        internal Vault(Policy policy, VaultOptions vaultOptions)
        {
            Policy = policy;
            _vaultOptions = vaultOptions;
        }

        /// <summary>A vault for the given options, with opaque placeholders unless told otherwise.</summary>
        public static Vault Create(RedactOptions? options = null, VaultOptions? vaultOptions = null) =>
            Policy.Compile(options).CreateVault(vaultOptions);

        /// <summary>The policy this vault redacts with.</summary>
        public Policy Policy { get; }

        private string Mint(string value, string detectorId)
        {
            if (_byValue.TryGetValue(value, out string? existing)) return existing;
            int index = _counts.TryGetValue(detectorId, out int count) ? count + 1 : 1;
            _counts[detectorId] = index;
            string placeholder = _vaultOptions.Placeholder(detectorId, index);
            if (_byPlaceholder.TryGetValue(placeholder, out string? collision) && !string.Equals(collision, value, StringComparison.Ordinal))
            {
                throw new FlareRedactException("the placeholder generator produced a duplicate token for " + detectorId);
            }
            _byValue[value] = placeholder;
            _byPlaceholder[placeholder] = value;
            _entries.Add(new KeyValuePair<string, string>(placeholder, value));
            return placeholder;
        }

        /// <summary>
        /// Replace every secret in a text with a stable placeholder. A value found inside a JSON
        /// document is stored decoded, so restoring it into JSON escapes it exactly once and
        /// restoring it into prose gives the value.
        /// </summary>
        public string RedactString(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            lock (_lock) return RedactStringLocked(text);
        }

        private string RedactStringLocked(string text)
        {
            int json = -1;
            return Policy.Rewrite(text, hit =>
            {
                if (json < 0) json = Restorers.IsJsonDocument(text) ? 1 : 0;
                string value = hit.Value;
                if (json == 1) value = Restorers.DecodeJsonStringContent(value) ?? value;
                return Mint(value, hit.Detector.Id);
            });
        }

        /// <summary>
        /// Replace every secret reachable from a value with a stable placeholder, preserving its
        /// shape (see <see cref="FlareRedact.Policy.Redact"/>). Every string and number under a
        /// sensitive key gets one; a number restores as its text.
        /// </summary>
        public object? Redact(object? value)
        {
            lock (_lock)
            {
                return new Policy.Walker(RedactStringLocked, Policy.IsSensitiveKey,
                    text => Policy.Allows(text) ? null : Mint(text, Detector.SensitiveKey.Id)).Walk(value, 0);
            }
        }

        /// <summary>Placeholder, original pairs in the order they were minted.</summary>
        public IReadOnlyList<KeyValuePair<string, string>> Entries
        {
            get
            {
                lock (_lock) return _entries.ToArray();
            }
        }

        /// <summary>The number of distinct values replaced so far.</summary>
        public int Count
        {
            get
            {
                lock (_lock) return _entries.Count;
            }
        }

        /// <summary>
        /// Put the originals back into a text. When the text is a JSON object or array, the
        /// originals go in JSON-escaped.
        /// </summary>
        public string RestoreString(string text) => Restorers.JsonAware(Entries)(text);

        /// <summary>Put the originals back into any supported value.</summary>
        public object? Restore(object? value) => new Policy.Walker(Restorers.JsonAware(Entries), null).Walk(value, 0);

        /// <summary>A restorer for streamed output, safe across chunk boundaries.</summary>
        public StreamRestorer Stream() => new StreamRestorer(Entries);

        /// <summary>A stream restorer for output that is JSON, such as tool-call arguments.</summary>
        public StreamRestorer StreamJson() => new StreamRestorer(Restorers.EscapeForJson(Entries));
    }

    /// <summary>
    /// Putting originals back. Every restorer here is single-pass and matches longer placeholders
    /// first, so a token that is a prefix of another cannot clobber its peer and restore the wrong
    /// secret.
    /// </summary>
    public static class Restorers
    {
        /// <summary>A single-pass restorer for placeholder to original pairs.</summary>
        public static Func<string, string> Plain(IEnumerable<KeyValuePair<string, string>> entries)
        {
            // Longest first; OrderBy is stable, so equal lengths keep mint order.
            List<KeyValuePair<string, string>> ordered = entries
                .Where(entry => !string.IsNullOrEmpty(entry.Key))
                .OrderByDescending(entry => entry.Key.Length)
                .ToList();
            if (ordered.Count == 0) return text => text;
            var lookup = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> entry in ordered) lookup[entry.Key] = entry.Value;
            var pattern = new Regex(string.Join("|", ordered.Select(entry => Regex.Escape(entry.Key))),
                RegexOptions.CultureInvariant);
            return text =>
            {
                if (text == null) return null!;
                return pattern.Replace(text, match => lookup.TryGetValue(match.Value, out string? original) ? original : match.Value);
            };
        }

        /// <summary>
        /// The pairs with each original escaped for the inside of a JSON string literal (SPEC §11).
        /// A placeholder can only sit inside a string in valid JSON, so an original spliced in this
        /// form keeps the JSON valid, and quotes, backslashes or control characters in it cannot
        /// end the string and add or replace fields.
        /// </summary>
        public static IReadOnlyList<KeyValuePair<string, string>> EscapeForJson(IEnumerable<KeyValuePair<string, string>> entries) =>
            entries.Select(entry => new KeyValuePair<string, string>(entry.Key, Json.Escape(entry.Value))).ToList();

        /// <summary>
        /// <see cref="Plain"/>, except that a string which is a JSON object or array (tool call
        /// arguments, JSON-mode output) gets the originals JSON-escaped, so it is still valid JSON
        /// with the same structure after the restore.
        /// </summary>
        public static Func<string, string> JsonAware(IReadOnlyList<KeyValuePair<string, string>> entries)
        {
            if (entries.Count == 0) return text => text;
            Func<string, string> plain = Plain(entries);
            Func<string, string>? escaped = null;
            return text =>
            {
                if (text == null) return null!;
                string restored = plain(text);
                if (string.Equals(restored, text, StringComparison.Ordinal) || !IsJsonDocument(text)) return restored;
                Func<string, string> json = escaped ??= Plain(EscapeForJson(entries));
                return json(text);
            };
        }

        /// <summary>Whether a text is a complete JSON object or array.</summary>
        public static bool IsJsonDocument(string text)
        {
            int i = 0;
            while (i < text.Length && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r')) i++;
            if (i >= text.Length || (text[i] != '{' && text[i] != '[')) return false;
            return Json.IsValid(text);
        }

        /// <summary>
        /// A text read as the content of a JSON string literal, or null when it is not valid
        /// content: an unescaped quote or control character, an unknown or cut-off escape, or a
        /// <c>\u</c> escape that leaves a lone surrogate.
        /// </summary>
        internal static string? DecodeJsonStringContent(string text)
        {
            var output = new StringBuilder(text.Length);
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (c == '"' || c < 0x20) return null;
                if (c != '\\')
                {
                    output.Append(c);
                    i++;
                    continue;
                }
                char next = i + 1 < text.Length ? text[i + 1] : '\0';
                switch (next)
                {
                    case '"':
                    case '\\':
                    case '/':
                        output.Append(next);
                        i += 2;
                        continue;
                    case 'b':
                        output.Append('\b');
                        i += 2;
                        continue;
                    case 'f':
                        output.Append('\f');
                        i += 2;
                        continue;
                    case 'n':
                        output.Append('\n');
                        i += 2;
                        continue;
                    case 'r':
                        output.Append('\r');
                        i += 2;
                        continue;
                    case 't':
                        output.Append('\t');
                        i += 2;
                        continue;
                    case 'u':
                        break;
                    default:
                        return null;
                }
                int unit = Json.Hex4(text, i + 2);
                i += 6;
                if (unit < 0 || (unit >= 0xDC00 && unit <= 0xDFFF)) return null;
                if (unit >= 0xD800 && unit <= 0xDBFF)
                {
                    int low = i + 1 < text.Length && text[i] == '\\' && text[i + 1] == 'u' ? Json.Hex4(text, i + 2) : -1;
                    if (low < 0xDC00 || low > 0xDFFF) return null;
                    output.Append((char)unit).Append((char)low);
                    i += 6;
                    continue;
                }
                output.Append((char)unit);
            }
            return output.ToString();
        }
    }

    /// <summary>
    /// Restores placeholders in a stream, even when one is split across chunks. It holds back the
    /// longest suffix of what it has buffered that could still be the start of a placeholder;
    /// everything before that is emitted at once.
    /// </summary>
    /// <remarks>Not thread-safe: one restorer belongs to one stream.</remarks>
    public sealed class StreamRestorer
    {
        private readonly Func<string, string> _restore;
        private readonly List<string> _placeholders;
        private readonly StringBuilder _buffer = new StringBuilder();

        /// <summary>A restorer for placeholder, original pairs.</summary>
        public StreamRestorer(IEnumerable<KeyValuePair<string, string>> entries)
        {
            List<KeyValuePair<string, string>> list = entries.ToList();
            _restore = Restorers.Plain(list);
            _placeholders = list.Select(entry => entry.Key).ToList();
        }

        private int PendingPrefixLength()
        {
            int keep = 0;
            foreach (string placeholder in _placeholders)
            {
                int limit = Math.Min(_buffer.Length, placeholder.Length - 1);
                for (int length = limit; length > keep; length--)
                {
                    if (EndsWith(placeholder, length))
                    {
                        keep = length;
                        break;
                    }
                }
            }
            return keep;
        }

        private bool EndsWith(string placeholder, int length)
        {
            int offset = _buffer.Length - length;
            for (int i = 0; i < length; i++)
            {
                if (_buffer[offset + i] != placeholder[i]) return false;
            }
            return true;
        }

        /// <summary>Feed a chunk; returns the text that is safe to show now, restored.</summary>
        public string Push(string chunk)
        {
            _buffer.Append(chunk);
            int cut = _buffer.Length - PendingPrefixLength();
            string emit = _buffer.ToString(0, cut);
            _buffer.Remove(0, cut);
            return _restore(emit);
        }

        /// <summary>Whatever is still held back, once the stream has ended.</summary>
        public string Flush()
        {
            string output = _restore(_buffer.ToString());
            _buffer.Clear();
            return output;
        }
    }

    /// <summary>
    /// A conversation-scoped vault. One session keeps one vault, so the same value maps to the same
    /// placeholder across every turn: redact the user's message on the way in, restore the model's
    /// answer on the way out.
    /// </summary>
    public sealed class Session
    {
        private readonly Policy _policy;
        private readonly VaultOptions _vaultOptions;
        private volatile Vault _vault;

        /// <summary>A session for the given options, with opaque placeholders unless told otherwise.</summary>
        public Session(RedactOptions? options = null, VaultOptions? vaultOptions = null)
        {
            _policy = Policy.Compile(options);
            _vaultOptions = vaultOptions ?? VaultOptions.Default;
            _vault = _policy.CreateVault(_vaultOptions);
        }

        /// <summary>The vault holding this conversation's mappings.</summary>
        public Vault Vault => _vault;

        /// <summary>The same shape with placeholders in place of secrets.</summary>
        public object? Redact(object? value) => _vault.Redact(value);

        /// <summary>The message with placeholders in place of secrets.</summary>
        public string RedactString(string text) => _vault.RedactString(text);

        /// <summary>The reply with the originals back.</summary>
        public object? Restore(object? value) => _vault.Restore(value);

        /// <summary>The reply with the originals back.</summary>
        public string RestoreString(string text) => _vault.RestoreString(text);

        /// <summary>A restorer for a streamed reply.</summary>
        public StreamRestorer Stream() => _vault.Stream();

        /// <summary>A restorer for a streamed reply that is JSON.</summary>
        public StreamRestorer StreamJson() => _vault.StreamJson();

        /// <summary>Start a fresh conversation with no carried-over mappings.</summary>
        public void Reset() => _vault = _policy.CreateVault(_vaultOptions);
    }
}
