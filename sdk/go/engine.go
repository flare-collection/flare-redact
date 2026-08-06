package flareredact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The FRS-1 scan and redact engine.
//
// Everything this package does reduces to one function: given a string, produce
// the set of spans that must not survive, then rewrite the string once. The
// rest — structured values, vaults, the slog handler, the HTTP transport — is
// plumbing around this file.
//
// Two decisions are worth knowing about. Overlap resolution is maximum-weight
// interval scheduling rather than first-match, so a value that is both an
// OpenRouter key and a high-entropy string is masked the same way regardless of
// what else is on the line. And limits fail closed: oversized input returns an
// error instead of partially redacted text, because a caller cannot tell
// partially redacted output from clean output.

// Mode selects how a matched value is replaced.
type Mode string

const (
	ModeMask      Mode = "mask"
	ModeLabel     Mode = "label"
	ModeHash      Mode = "hash"
	ModePseudonym Mode = "pseudonym"
	ModeSurrogate Mode = "surrogate"
)

// Default limits, in bytes and findings per scanned string.
const (
	DefaultMaxInputLength = 16 * 1024 * 1024
	DefaultMaxFindings    = 50_000
)

// maxDepth bounds structural recursion. Data from json.Unmarshal is acyclic, but
// a hand-built []any can point at itself, and a redactor must not hang on it.
const maxDepth = 512

// Term is a caller-supplied word to always catch, with an optional replacement.
type Term struct {
	Term    string
	Replace string
}

// Options is everything that shapes a redaction. The zero value is a working
// configuration: default detectors, mask mode, key redaction on.
type Options struct {
	// Only uses exactly these detector ids or tags, ignoring defaults.
	Only []string
	// Enable turns on non-default detectors by id or tag.
	Enable []string
	// Disable turns off detectors by id or tag.
	Disable []string
	// Mode selects the replacement strategy. Empty means ModeMask.
	Mode Mode
	// Mask is a fixed replacement string. It wins over Mode when set.
	Mask string
	// MaskFunc replaces a matched value. It wins over Mask and Mode.
	MaskFunc func(value string, detector *Detector) string
	// TransformSecret keys ModeHash, ModePseudonym and ModeSurrogate.
	TransformSecret string
	// DisableKeyRedaction turns off the "sensitive by field name" rule.
	DisableKeyRedaction bool
	// KeyNames replaces the built-in sensitive-name test with an exact list.
	KeyNames []string
	// Allow lists values that are never redacted.
	Allow []string
	// AllowFunc is an additional predicate for values that are never redacted.
	AllowFunc func(value string) bool
	// Terms are your own words to always catch.
	Terms []Term
	// TermsCaseSensitive matches Terms exactly as written.
	TermsCaseSensitive bool
	// MinConfidence drops findings scored below it.
	MinConfidence float64
	// RefineConfidence lets the learned classifier adjust generic detectors.
	RefineConfidence bool
	// IncludeValues puts raw matched values in findings. Unsafe for logs.
	IncludeValues bool
	// MaxInputLength caps the bytes of a single scanned string. 0 uses the default.
	MaxInputLength int
	// MaxFindings caps findings per scanned string. 0 uses the default.
	MaxFindings int
	// Pack overrides the bundled detector pack.
	Pack *Pack
}

// Finding is one thing the scanner would redact, and why.
type Finding struct {
	Detector   string  `json:"detector"`
	Label      string  `json:"label"`
	Why        string  `json:"why"`
	Risk       string  `json:"risk"`
	Confidence float64 `json:"confidence"`
	// Start, End, Line and Column are rune offsets and one-based positions in
	// the scanned string. They are -1 for a finding produced by a field name.
	Start  int `json:"start"`
	End    int `json:"end"`
	Line   int `json:"line"`
	Column int `json:"column"`
	// Path locates the finding inside a structured value; empty at the top level.
	Path string `json:"path,omitempty"`
	// Value is populated only when Options.IncludeValues is set.
	Value string `json:"value,omitempty"`
}

// Summary counts findings without disclosing any of them.
type Summary struct {
	Total      int            `json:"total"`
	ByDetector map[string]int `json:"byDetector"`
	ByRisk     map[string]int `json:"byRisk"`
}

// LimitError reports that a configured limit was exceeded. Nothing was redacted:
// a partially redacted result the caller cannot detect is worse than an error.
type LimitError struct{ Reason string }

func (e *LimitError) Error() string { return "flareredact: " + e.Reason }

var riskWeight = map[string]float64{
	RiskCritical: 1e9,
	RiskHigh:     1e6,
	RiskMedium:   1e3,
	RiskLow:      1,
}

// refineStrength is how far the learned model may move a base confidence score.
const refineStrength = 0.4

// Invisible characters an attacker can splice through a secret to defeat a
// naive matcher. Stripped before matching; see normalisedView.
// Written as escapes: a literal U+FEFF is rejected by the Go compiler outside
// the first byte of a file.
const zeroWidthRunes = "\u200b\u200c\u200d\u2060\ufeff"

// Policy is one compiled set of options, reusable everywhere. Building it
// resolves the detector list, the mask function and the key and allow tests
// once — and guarantees your logs, your HTTP layer and your prompts agree on
// what "sensitive" means.
type Policy struct {
	options   Options
	pack      *Pack
	detectors []*Detector
	allow     func(string) bool
	matchKey  func(string) bool
	replace   func(value string, detector *Detector) string

	maxInputLength int
	maxFindings    int
}

var sensitiveKeyDetector = &Detector{
	ID:         "sensitive_key",
	Label:      "Sensitive field",
	Why:        "A value stored under a field name that is sensitive by convention.",
	Risk:       RiskCritical,
	Confidence: 0.98,
	mask:       func(string) string { return "***" },
}

// Compile turns options into a reusable policy.
func Compile(options Options) (*Policy, error) {
	pack := options.Pack
	if pack == nil {
		loaded, err := CorePack()
		if err != nil {
			return nil, err
		}
		pack = loaded
	}

	detectors, err := resolveDetectors(pack, options)
	if err != nil {
		return nil, err
	}
	replace, err := makeReplacer(options)
	if err != nil {
		return nil, err
	}

	policy := &Policy{
		options:        options,
		pack:           pack,
		detectors:      detectors,
		allow:          makeAllow(options),
		matchKey:       makeKeyMatcher(options),
		replace:        replace,
		maxInputLength: options.MaxInputLength,
		maxFindings:    options.MaxFindings,
	}
	if policy.maxInputLength <= 0 {
		policy.maxInputLength = DefaultMaxInputLength
	}
	if policy.maxFindings <= 0 {
		policy.maxFindings = DefaultMaxFindings
	}
	return policy, nil
}

// Detectors returns the resolved detector list, in evaluation order.
func (p *Policy) Detectors() []*Detector { return p.detectors }

func resolveDetectors(pack *Pack, options Options) ([]*Detector, error) {
	var chosen []*Detector
	matchesAny := func(detector *Detector, selectors []string) bool {
		for _, selector := range selectors {
			if detector.MatchesSelector(selector) {
				return true
			}
		}
		return false
	}
	for _, detector := range pack.Detectors {
		if len(options.Only) > 0 {
			if matchesAny(detector, options.Only) {
				chosen = append(chosen, detector)
			}
			continue
		}
		if (detector.Default || matchesAny(detector, options.Enable)) && !matchesAny(detector, options.Disable) {
			chosen = append(chosen, detector)
		}
	}
	terms, err := buildTermsDetector(options.Terms, options.TermsCaseSensitive)
	if err != nil {
		return nil, err
	}
	if terms != nil {
		return append([]*Detector{terms}, chosen...), nil
	}
	return chosen, nil
}

// buildTermsDetector matches caller-supplied words longest-first on Unicode word
// boundaries, so "Bluebird" does not fire inside "Bluebirds".
func buildTermsDetector(terms []Term, caseSensitive bool) (*Detector, error) {
	if len(terms) == 0 {
		return nil, nil
	}
	ordered := make([]Term, 0, len(terms))
	for _, term := range terms {
		if term.Term != "" {
			ordered = append(ordered, term)
		}
	}
	if len(ordered) == 0 {
		return nil, nil
	}
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i].Term) > len(ordered[j].Term) })

	parts := make([]string, len(ordered))
	for i, term := range ordered {
		parts[i] = regexp.QuoteMeta(term.Term)
	}
	body := "(?:" + strings.Join(parts, "|") + ")"
	if !caseSensitive {
		body = "(?i)" + body
	}
	regex, err := regexp.Compile(body)
	if err != nil {
		return nil, fmt.Errorf("flareredact: invalid term list: %w", err)
	}

	key := func(text string) string {
		if caseSensitive {
			return text
		}
		return strings.ToLower(text)
	}
	replacements := make(map[string]string, len(ordered))
	for _, term := range ordered {
		replacement := term.Replace
		if replacement == "" {
			replacement = "***"
		}
		replacements[key(term.Term)] = replacement
	}

	return &Detector{
		ID:         "custom_term",
		Label:      "Custom term",
		Why:        "A term you configured as sensitive.",
		Risk:       RiskHigh,
		Confidence: 0.92,
		Default:    true,
		Tags:       []string{"custom"},
		regex:      regex,
		unicodeBoundary: true,
		mask: func(value string) string {
			if replacement, ok := replacements[key(value)]; ok {
				return replacement
			}
			return "***"
		},
	}, nil
}

func makeAllow(options Options) func(string) bool {
	if len(options.Allow) == 0 && options.AllowFunc == nil {
		return func(string) bool { return false }
	}
	allowed := make(map[string]struct{}, len(options.Allow))
	for _, value := range options.Allow {
		allowed[value] = struct{}{}
	}
	extra := options.AllowFunc
	return func(value string) bool {
		if _, ok := allowed[value]; ok {
			return true
		}
		return extra != nil && extra(value)
	}
}

func makeKeyMatcher(options Options) func(string) bool {
	if options.DisableKeyRedaction {
		return func(string) bool { return false }
	}
	if len(options.KeyNames) > 0 {
		names := make(map[string]struct{}, len(options.KeyNames))
		for _, name := range options.KeyNames {
			names[strings.ToLower(name)] = struct{}{}
		}
		return func(name string) bool {
			_, ok := names[strings.ToLower(name)]
			return ok
		}
	}
	return isSensitiveKeyName
}

func makeReplacer(options Options) (func(string, *Detector) string, error) {
	if options.MaskFunc != nil {
		return options.MaskFunc, nil
	}
	if options.Mask != "" {
		mask := options.Mask
		return func(string, *Detector) string { return mask }, nil
	}
	secret := options.TransformSecret
	mode := options.Mode
	if mode == "" {
		mode = ModeMask
	}
	switch mode {
	case ModeMask:
		return func(value string, detector *Detector) string {
			if detector.mask == nil {
				return "***"
			}
			return detector.mask(value)
		}, nil
	case ModeLabel:
		return func(_ string, detector *Detector) string { return "[REDACTED:" + detector.ID + "]" }, nil
	case ModeHash:
		if secret == "" {
			return nil, ErrMissingSecret
		}
		return func(value string, detector *Detector) string {
			return detector.ID + "_" + HMACFingerprint(secret, value, 16)
		}, nil
	case ModePseudonym:
		if secret == "" {
			return nil, ErrMissingSecret
		}
		return func(value string, _ *Detector) string { return Pseudonymize(value, secret) }, nil
	case ModeSurrogate:
		if secret == "" {
			return nil, ErrMissingSecret
		}
		return func(value string, detector *Detector) string { return Surrogate(value, detector.ID, secret) }, nil
	}
	return nil, fmt.Errorf("flareredact: unknown mode %q", mode)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

type hit struct {
	detector   *Detector
	start      int // byte offset in the original string
	end        int
	value      string
	confidence float64
	weight     float64
}

// normalisedView strips zero-width characters, keeping a map from each byte of
// the stripped text back to its byte offset in the original. Splicing U+200B
// between the letters of a password defeats a naive matcher; matching on the
// stripped text while replacing in the original defeats the splice.
func normalisedView(text string) (string, []int) {
	if !strings.ContainsAny(text, zeroWidthRunes) {
		return text, nil
	}
	var builder strings.Builder
	builder.Grow(len(text))
	source := make([]int, 0, len(text)+1)
	for offset, r := range text {
		if strings.ContainsRune(zeroWidthRunes, r) {
			continue
		}
		size := utf8.RuneLen(r)
		builder.WriteRune(r)
		for k := 0; k < size; k++ {
			source = append(source, offset+k)
		}
	}
	source = append(source, len(text))
	return builder.String(), source
}

// runeOffsets maps every byte offset of text to the rune offset it belongs to,
// so findings can report positions in the same unit as the other engines.
func runeOffsets(text string) []int {
	out := make([]int, len(text)+1)
	runes := 0
	for i := 0; i < len(text); {
		_, size := utf8.DecodeRuneInString(text[i:])
		for k := 0; k < size; k++ {
			out[i+k] = runes
		}
		i += size
		runes++
	}
	out[len(text)] = runes
	return out
}

func clampToRuneStart(text string, offset int) int {
	for offset > 0 && offset < len(text) && !utf8.RuneStart(text[offset]) {
		offset--
	}
	return offset
}

func (p *Policy) scoreConfidence(detector *Detector, text string, start, end int) float64 {
	score := detector.Confidence
	if detector.ctxPositive != nil || detector.ctxNegative != nil {
		radius := detector.ctxWindow
		lo := clampToRuneStart(text, max(0, start-radius))
		hi := min(len(text), end+radius)
		if hi < len(text) {
			hi = clampToRuneStart(text, hi)
		}
		nearby := text[lo:hi]
		if detector.ctxPositive != nil && detector.ctxPositive.MatchString(nearby) {
			score += 0.06
		}
		if detector.ctxNegative != nil && detector.ctxNegative.MatchString(nearby) {
			score -= 0.25
		}
	}
	if p.options.RefineConfidence && detector.Refine && p.pack.Model != nil {
		lo := clampToRuneStart(text, max(0, start-64))
		hi := min(len(text), end+64)
		if hi < len(text) {
			hi = clampToRuneStart(text, hi)
		}
		score += (SecretProbability(text[start:end], text[lo:hi], p.pack.Model) - 0.5) * refineStrength
	}
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func (p *Policy) scanString(text string) ([]hit, error) {
	if len(text) > p.maxInputLength {
		return nil, &LimitError{Reason: fmt.Sprintf("input length %d exceeds the configured limit of %d", len(text), p.maxInputLength)}
	}
	subject, source := normalisedView(text)
	lowered := ""
	loweredReady := false
	var hits []hit

	for _, detector := range p.detectors {
		if len(detector.Prefilter) > 0 {
			if !loweredReady {
				lowered = strings.ToLower(subject)
				loweredReady = true
			}
			found := false
			for _, literal := range detector.Prefilter {
				if strings.Contains(lowered, literal) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		for _, match := range detector.regex.FindAllStringSubmatchIndex(subject, -1) {
			ns, ne := match[2*detector.capture], match[2*detector.capture+1]
			if ns < 0 || ne <= ns {
				continue
			}
			if !detector.boundaryOK(subject, ns, ne) {
				continue
			}

			normalisedValue := subject[ns:ne]
			if detector.rejects(normalisedValue) || !detector.validates(normalisedValue) {
				continue
			}

			start, end := ns, ne
			if source != nil {
				start, end = source[ns], source[ne-1]+1
			}
			value := text[start:end]
			if p.allow(value) || (value != normalisedValue && p.allow(normalisedValue)) {
				continue
			}

			confidence := p.scoreConfidence(detector, text, start, end)
			if confidence < p.options.MinConfidence {
				continue
			}

			hits = append(hits, hit{
				detector:   detector,
				start:      start,
				end:        end,
				value:      value,
				confidence: confidence,
				weight: riskWeight[detector.Risk] +
					10*float64(detector.Priority) +
					confidence +
					float64(end-start)/1_000_000,
			})
			if len(hits) > p.maxFindings {
				return nil, &LimitError{Reason: fmt.Sprintf("finding count exceeds the configured limit of %d", p.maxFindings)}
			}
		}
	}

	if len(hits) < 2 {
		return hits, nil
	}
	return selectNonOverlapping(hits), nil
}

func (d *Detector) boundaryOK(subject string, start, end int) bool {
	if d.unicodeBoundary {
		if start > 0 {
			r, _ := utf8.DecodeLastRuneInString(subject[:start])
			if isUnicodeWordRune(r) {
				return false
			}
		}
		if end < len(subject) {
			r, _ := utf8.DecodeRuneInString(subject[end:])
			if isUnicodeWordRune(r) {
				return false
			}
		}
		return true
	}
	if d.before != nil && start > 0 && d.before.has(subject[start-1]) {
		return false
	}
	if d.after != nil && end < len(subject) && d.after.has(subject[end]) {
		return false
	}
	return true
}

func (d *Detector) rejects(value string) bool {
	for _, re := range d.reject {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func (d *Detector) validates(value string) bool {
	for _, validator := range d.validators {
		if !validator(value) {
			return false
		}
	}
	return true
}

// selectNonOverlapping keeps the maximum-weight set of non-overlapping spans.
// First-match-wins would make masking depend on detector order, so the same
// secret could be masked differently depending on what else was nearby.
func selectNonOverlapping(hits []hit) []hit {
	ordered := make([]hit, len(hits))
	copy(ordered, hits)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].end != ordered[j].end {
			return ordered[i].end < ordered[j].end
		}
		return ordered[i].start < ordered[j].start
	})

	count := len(ordered)
	previous := make([]int, count)
	for i := 0; i < count; i++ {
		low, high, found := 0, i-1, -1
		for low <= high {
			mid := (low + high) / 2
			if ordered[mid].end <= ordered[i].start {
				found = mid
				low = mid + 1
			} else {
				high = mid - 1
			}
		}
		previous[i] = found
	}

	best := make([]float64, count+1)
	for i := 1; i <= count; i++ {
		include := ordered[i-1].weight + best[previous[i-1]+1]
		best[i] = max(best[i-1], include)
	}

	var selected []hit
	for i := count; i > 0; {
		include := ordered[i-1].weight + best[previous[i-1]+1]
		if include > best[i-1] {
			selected = append(selected, ordered[i-1])
			i = previous[i-1] + 1
		} else {
			i--
		}
	}
	for left, right := 0, len(selected)-1; left < right; left, right = left+1, right-1 {
		selected[left], selected[right] = selected[right], selected[left]
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].start != selected[j].start {
			return selected[i].start < selected[j].start
		}
		return selected[i].end < selected[j].end
	})
	return selected
}

// RedactString rewrites one string in a single pass. Replacements are never
// rescanned, so a mask can never itself be masked.
func (p *Policy) RedactString(text string) (string, error) {
	return p.rewrite(text, func(h hit) string { return p.replace(h.value, h.detector) })
}

func (p *Policy) rewrite(text string, replacement func(hit) string) (string, error) {
	hits, err := p.scanString(text)
	if err != nil {
		return "", err
	}
	if len(hits) == 0 {
		return text, nil
	}
	var out strings.Builder
	out.Grow(len(text))
	cursor := 0
	for _, h := range hits {
		out.WriteString(text[cursor:h.start])
		out.WriteString(replacement(h))
		cursor = h.end
	}
	out.WriteString(text[cursor:])
	return out.String(), nil
}

// ScanString lists what would be redacted in one string, and why.
func (p *Policy) ScanString(text string) ([]Finding, error) {
	hits, err := p.scanString(text)
	if err != nil {
		return nil, err
	}
	if len(hits) == 0 {
		return nil, nil
	}
	offsets := runeOffsets(text)
	findings := make([]Finding, 0, len(hits))
	for _, h := range hits {
		line, column := locate(text, h.start)
		finding := Finding{
			Detector:   h.detector.ID,
			Label:      h.detector.Label,
			Why:        h.detector.Why,
			Risk:       h.detector.Risk,
			Confidence: h.confidence,
			Start:      offsets[h.start],
			End:        offsets[h.end],
			Line:       line,
			Column:     column,
		}
		if p.options.IncludeValues {
			finding.Value = h.value
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func locate(text string, offset int) (int, int) {
	head := text[:offset]
	line := 1 + strings.Count(head, "\n")
	lineStart := strings.LastIndex(head, "\n") + 1
	return line, utf8.RuneCountInString(text[lineStart:offset]) + 1
}

func isUnicodeWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
