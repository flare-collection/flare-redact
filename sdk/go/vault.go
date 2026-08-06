package flareredact

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Reversible redaction.
//
// Masking is one-way, which is right for logs and wrong for a model call. A
// vault swaps each secret for a stable placeholder and remembers the mapping,
// so you can send the redacted text to a model and put the originals back into
// its answer. The model never sees the data; your user still gets the right
// reply.
//
// Placeholders are opaque by default — random, not numbered — so the text that
// leaves your process does not also disclose how many distinct people or
// secrets the conversation involves.

// PlaceholderStyle selects the shape of minted placeholders.
type PlaceholderStyle string

const (
	// PlaceholderOpaque mints [FR_EMAIL_<random hex>]. Use this in production.
	PlaceholderOpaque PlaceholderStyle = "opaque"
	// PlaceholderReadable mints [EMAIL_1]. Predictable, so local debugging only.
	PlaceholderReadable PlaceholderStyle = "readable"
)

// VaultOptions configures placeholder minting.
type VaultOptions struct {
	Style PlaceholderStyle
	// Placeholder overrides Style entirely. It must never return the same token
	// for two different values.
	Placeholder func(detectorID string, index int) string
}

// Vault is a reversible redactor. The same value always maps to the same
// placeholder within one vault, so references survive a round trip: "email the
// address in message 1" still resolves after redaction.
type Vault struct {
	policy *Policy
	format func(detectorID string, index int) string

	mu            sync.Mutex
	byValue       map[string]string
	byPlaceholder map[string]string
	order         []string
	counts        map[string]int
}

func opaquePlaceholder(detectorID string, _ int) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing means the platform has no entropy source; a
		// predictable placeholder would be worse than a loud failure.
		panic(fmt.Errorf("flareredact: cannot mint an opaque placeholder: %w", err))
	}
	return "[FR_" + strings.ToUpper(detectorID) + "_" + hex.EncodeToString(buf) + "]"
}

func readablePlaceholder(detectorID string, index int) string {
	return "[" + strings.ToUpper(detectorID) + "_" + strconv.Itoa(index) + "]"
}

// NewVault compiles options into a reversible redactor.
func NewVault(options Options, vaultOptions VaultOptions) (*Vault, error) {
	policy, err := Compile(options)
	if err != nil {
		return nil, err
	}
	return NewVaultWithPolicy(policy, vaultOptions), nil
}

// NewVaultWithPolicy reuses an already-compiled policy.
func NewVaultWithPolicy(policy *Policy, vaultOptions VaultOptions) *Vault {
	format := vaultOptions.Placeholder
	if format == nil {
		if vaultOptions.Style == PlaceholderReadable {
			format = readablePlaceholder
		} else {
			format = opaquePlaceholder
		}
	}
	return &Vault{
		policy:        policy,
		format:        format,
		byValue:       map[string]string{},
		byPlaceholder: map[string]string{},
		counts:        map[string]int{},
	}
}

func (v *Vault) mint(value, detectorID string) (string, error) {
	if existing, ok := v.byValue[value]; ok {
		return existing, nil
	}
	v.counts[detectorID]++
	placeholder := v.format(detectorID, v.counts[detectorID])
	if collision, ok := v.byPlaceholder[placeholder]; ok && collision != value {
		return "", fmt.Errorf("flareredact: placeholder generator produced a duplicate token for %s", detectorID)
	}
	v.byValue[value] = placeholder
	v.byPlaceholder[placeholder] = value
	v.order = append(v.order, placeholder)
	return placeholder, nil
}

// RedactString replaces every secret in text with a stable placeholder.
func (v *Vault) RedactString(text string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.redactStringLocked(text)
}

func (v *Vault) redactStringLocked(text string) (string, error) {
	var mintErr error
	out, err := v.policy.rewrite(text, func(h hit) string {
		placeholder, err := v.mint(h.value, h.detector.ID)
		if err != nil && mintErr == nil {
			mintErr = err
		}
		return placeholder
	})
	if mintErr != nil {
		return "", mintErr
	}
	return out, err
}

// Redact replaces every secret reachable from value with a stable placeholder.
func (v *Vault) Redact(value any) (any, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.redactValue(value, 0)
}

func (v *Vault) redactValue(value any, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrTooDeep
	}
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return v.redactStringLocked(typed)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for _, key := range sortedKeys(typed) {
			if text, ok := typed[key].(string); ok {
				replaced, err := v.redactFieldLocked(key, text)
				if err != nil {
					return nil, err
				}
				out[key] = replaced
				continue
			}
			replaced, err := v.redactValue(typed[key], depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil
	case map[string]string:
		out := make(map[string]string, len(typed))
		for _, key := range sortedKeys(typed) {
			replaced, err := v.redactFieldLocked(key, typed[key])
			if err != nil {
				return nil, err
			}
			out[key] = replaced
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, entry := range typed {
			replaced, err := v.redactValue(entry, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil
	case []string:
		out := make([]string, len(typed))
		for i, entry := range typed {
			replaced, err := v.redactStringLocked(entry)
			if err != nil {
				return nil, err
			}
			out[i] = replaced
		}
		return out, nil
	default:
		return value, nil
	}
}

func (v *Vault) redactFieldLocked(key, value string) (string, error) {
	if v.policy.matchKey(key) && !v.policy.allow(value) {
		return v.mint(value, sensitiveKeyDetector.ID)
	}
	return v.redactStringLocked(value)
}

// Entries returns placeholder → original pairs in the order they were minted.
func (v *Vault) Entries() [][2]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([][2]string, 0, len(v.order))
	for _, placeholder := range v.order {
		out = append(out, [2]string{placeholder, v.byPlaceholder[placeholder]})
	}
	return out
}

// Size is the number of distinct values masked so far.
func (v *Vault) Size() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.byPlaceholder)
}

// RestoreString puts the originals back into text.
func (v *Vault) RestoreString(text string) string {
	return BuildRestorer(v.Entries())(text)
}

// Restore puts the originals back into any supported value.
func (v *Vault) Restore(value any) any {
	restore := BuildRestorer(v.Entries())
	return mapStrings(value, restore, 0)
}

// Stream returns a restorer for streamed output, safe across chunk boundaries.
func (v *Vault) Stream() *StreamRestorer {
	return NewStreamRestorer(v.Entries())
}

func mapStrings(value any, transform func(string) string, depth int) any {
	if depth > maxDepth {
		return value
	}
	switch typed := value.(type) {
	case string:
		return transform(typed)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, entry := range typed {
			out[key] = mapStrings(entry, transform, depth+1)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, entry := range typed {
			out[key] = transform(entry)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, entry := range typed {
			out[i] = mapStrings(entry, transform, depth+1)
		}
		return out
	case []string:
		out := make([]string, len(typed))
		for i, entry := range typed {
			out[i] = transform(entry)
		}
		return out
	default:
		return value
	}
}

// BuildRestorer returns a single-pass restorer for placeholder → original pairs.
// Longer placeholders are matched first, so a token that is a prefix of another
// cannot clobber its peer and restore the wrong secret.
func BuildRestorer(entries [][2]string) func(string) string {
	if len(entries) == 0 {
		return func(text string) string { return text }
	}
	ordered := make([][2]string, len(entries))
	copy(ordered, entries)
	sortByPlaceholderLength(ordered)
	pairs := make([]string, 0, len(ordered)*2)
	for _, entry := range ordered {
		pairs = append(pairs, entry[0], entry[1])
	}
	replacer := strings.NewReplacer(pairs...)
	return replacer.Replace
}

func sortByPlaceholderLength(entries [][2]string) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && len(entries[j][0]) > len(entries[j-1][0]); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

// StreamRestorer restores placeholders in a stream, even when one is split
// across chunks. It holds back the longest suffix of what it has buffered that
// could still turn out to be the start of a placeholder; everything before that
// is safe to emit immediately.
type StreamRestorer struct {
	restore      func(string) string
	placeholders []string
	buffer       string
}

// NewStreamRestorer builds a restorer for the given placeholder → original pairs.
func NewStreamRestorer(entries [][2]string) *StreamRestorer {
	placeholders := make([]string, 0, len(entries))
	for _, entry := range entries {
		placeholders = append(placeholders, entry[0])
	}
	return &StreamRestorer{restore: BuildRestorer(entries), placeholders: placeholders}
}

func (s *StreamRestorer) pendingPrefixLength() int {
	keep := 0
	for _, placeholder := range s.placeholders {
		limit := len(placeholder) - 1
		if len(s.buffer) < limit {
			limit = len(s.buffer)
		}
		for length := limit; length > keep; length-- {
			if strings.HasSuffix(s.buffer, placeholder[:length]) {
				keep = length
				break
			}
		}
	}
	return keep
}

// Push feeds a chunk and returns the text that is safe to display now.
func (s *StreamRestorer) Push(chunk string) string {
	s.buffer += chunk
	keep := s.pendingPrefixLength()
	cut := len(s.buffer) - keep
	emit := s.buffer[:cut]
	s.buffer = s.buffer[cut:]
	return s.restore(emit)
}

// Flush emits whatever is still held back once the stream ends.
func (s *StreamRestorer) Flush() string {
	out := s.restore(s.buffer)
	s.buffer = ""
	return out
}

// Session is a conversation-scoped vault. One session keeps one vault, so the
// same value maps to the same placeholder across every turn: mask the user's
// message on the way in, restore the model's answer on the way out.
type Session struct {
	options      Options
	vaultOptions VaultOptions
	vault        *Vault
}

// NewSession opens a conversation-scoped vault.
func NewSession(options Options, vaultOptions VaultOptions) (*Session, error) {
	vault, err := NewVault(options, vaultOptions)
	if err != nil {
		return nil, err
	}
	return &Session{options: options, vaultOptions: vaultOptions, vault: vault}, nil
}

// Vault exposes the underlying placeholder ↔ original map.
func (s *Session) Vault() *Vault { return s.vault }

// Redact masks a message before it reaches the model.
func (s *Session) Redact(value any) (any, error) { return s.vault.Redact(value) }

// Restore puts the originals back into the model's reply.
func (s *Session) Restore(value any) any { return s.vault.Restore(value) }

// Stream returns a restorer for a streamed reply.
func (s *Session) Stream() *StreamRestorer { return s.vault.Stream() }

// Reset starts a fresh conversation with no carried-over mappings.
func (s *Session) Reset() error {
	vault, err := NewVault(s.options, s.vaultOptions)
	if err != nil {
		return err
	}
	s.vault = vault
	return nil
}
