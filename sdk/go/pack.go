package flareredact

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// FRS-1 detector packs.
//
// A pack is data: patterns written in a restricted, engine-neutral subset plus
// named validators and mask strategies. Loading one compiles it into detectors
// this engine can run — and refuses anything it cannot run exactly as
// spec/SPEC.md describes. An unknown validator or a lookahead in a pattern is a
// load error, never a silently weakened check, because failing open is how a
// redactor leaks.

// SpecRevision is the FRS-1 revision this engine implements.
const SpecRevision = "FRS-1"

//go:embed detectors.json
var corePackJSON []byte

// Risk levels, most severe last.
const (
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

// Engine-side expansion of the two portable tokens. "(?s:.)" is any character
// including a line terminator; \p{L} is RE2's Unicode letter class.
const (
	tokenAny    = "(?s:.)"
	tokenLetter = `\p{L}`
)

// boundarySets are the neighbour characters a captured span may not touch.
// Every class is ASCII, so testing the adjacent byte is enough: the bytes of a
// multi-byte rune are all ≥ 0x80 and can never be members.
var boundarySets = map[string]string{
	"word":       lowerAlphabet + upperAlphabet + digitAlphabet + "_",
	"alnum":      lowerAlphabet + upperAlphabet + digitAlphabet,
	"digit":      digitAlphabet,
	"hex":        digitAlphabet + "abcdefABCDEF",
	"base64":     lowerAlphabet + upperAlphabet + digitAlphabet + "+/=",
	"base64url":  lowerAlphabet + upperAlphabet + digitAlphabet + "_+/=-",
	"word_dash":  lowerAlphabet + upperAlphabet + digitAlphabet + "_-",
}

type byteSet [256]bool

func newByteSet(members string) *byteSet {
	var set byteSet
	for i := 0; i < len(members); i++ {
		set[members[i]] = true
	}
	return &set
}

func (s *byteSet) has(b byte) bool { return s != nil && s[b] }

// Detector is one compiled rule: what it matches, how it is validated, and how
// a match is replaced.
type Detector struct {
	ID         string
	Label      string
	Why        string
	Risk       string
	Confidence float64
	Priority   int
	Default    bool
	Tags       []string
	Refine     bool
	Prefilter  []string

	regex   *regexp.Regexp
	capture int
	before  *byteSet
	after   *byteSet
	// unicodeBoundary is used by the caller-supplied terms detector, whose
	// boundaries must be Unicode-aware rather than ASCII: "Ünvan" should not
	// match inside "Ünvanlar".
	unicodeBoundary bool
	reject      []*regexp.Regexp
	validators  []func(string) bool
	mask        func(string) string
	ctxPositive *regexp.Regexp
	ctxNegative *regexp.Regexp
	ctxWindow   int
}

// MatchesSelector reports whether selector names this detector or one of its tags.
func (d *Detector) MatchesSelector(selector string) bool {
	if d.ID == selector {
		return true
	}
	for _, tag := range d.Tags {
		if tag == selector {
			return true
		}
	}
	return false
}

// Pack is a loaded, compiled detector pack.
type Pack struct {
	ID        string
	Version   string
	Title     string
	Detectors []*Detector
	Model     *ConfidenceModel

	byID map[string]*Detector
}

// Detector returns the detector with the given id, if the pack has one.
func (p *Pack) Detector(id string) (*Detector, bool) {
	d, ok := p.byID[id]
	return d, ok
}

type packDocument struct {
	Spec            string           `json:"spec"`
	ID              string           `json:"id"`
	Version         string           `json:"version"`
	Title           string           `json:"title"`
	ConfidenceModel *modelDocument   `json:"confidenceModel"`
	Detectors       []packDetectorDoc `json:"detectors"`
}

type modelDocument struct {
	Version  int       `json:"version"`
	Features []string  `json:"features"`
	Weights  []float64 `json:"weights"`
	Bias     float64   `json:"bias"`
}

type packDetectorDoc struct {
	ID         string                   `json:"id"`
	Label      string                   `json:"label"`
	Why        string                   `json:"why"`
	Pattern    string                   `json:"pattern"`
	Flags      string                   `json:"flags"`
	Capture    int                      `json:"capture"`
	Boundary   *boundaryDoc             `json:"boundary"`
	Reject     []string                 `json:"reject"`
	Validators []map[string]interface{} `json:"validators"`
	Mask       map[string]interface{}   `json:"mask"`
	Default    bool                     `json:"default"`
	Tags       []string                 `json:"tags"`
	Risk       string                   `json:"risk"`
	Priority   int                      `json:"priority"`
	Confidence float64                  `json:"confidence"`
	Refine     bool                     `json:"refine"`
	Prefilter  []string                 `json:"prefilter"`
	Context    *contextDoc              `json:"context"`
}

type boundaryDoc struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

type contextDoc struct {
	Positive string `json:"positive"`
	Negative string `json:"negative"`
	Window   int    `json:"window"`
}

func expandTokens(pattern string) string {
	return strings.NewReplacer("{{ANY}}", tokenAny, "{{L}}", tokenLetter).Replace(pattern)
}

const forbiddenEscapes = "bBdDwWsSpP123456789AZzGkK"

// assertPortable rejects constructs whose meaning differs between the FRS-1
// target engines: lookaround, backreferences, the \b \d \w \s shorthands,
// Unicode property escapes and anchors.
func assertPortable(pattern, where string) error {
	inClass := false
	for i := 0; i < len(pattern); {
		ch := pattern[i]
		if ch == '\\' {
			if i+1 >= len(pattern) {
				return fmt.Errorf("%s: pattern ends with a dangling backslash", where)
			}
			next := pattern[i+1]
			if strings.IndexByte(forbiddenEscapes, next) >= 0 {
				return fmt.Errorf("%s: '\\%c' is not portable across FRS-1 engines; write the character class out, or use {{ANY}} / {{L}}", where, next)
			}
			i += 2
			continue
		}
		if inClass {
			if ch == ']' {
				inClass = false
			}
			i++
			continue
		}
		if ch == '[' {
			i++
			if i < len(pattern) && pattern[i] == '^' {
				i++
			}
			if i < len(pattern) && pattern[i] == ']' {
				i++
			}
			inClass = true
			continue
		}
		if ch == '(' && i+1 < len(pattern) && pattern[i+1] == '?' {
			if i+2 >= len(pattern) || pattern[i+2] != ':' {
				return fmt.Errorf("%s: only '(...)' and '(?:...)' groups are portable across FRS-1 engines", where)
			}
			i += 3
			continue
		}
		if ch == '^' || ch == '$' {
			return fmt.Errorf("%s: anchors are not allowed inside a detector pattern", where)
		}
		i++
	}
	if inClass {
		return fmt.Errorf("%s: unterminated character class", where)
	}
	return nil
}

type anchorKind int

const (
	anchorNone anchorKind = iota
	anchorPrefix
	anchorFull
)

func compilePattern(pattern, flags, where string, portable bool, anchor anchorKind) (*regexp.Regexp, error) {
	if portable {
		if err := assertPortable(pattern, where); err != nil {
			return nil, err
		}
	}
	body := expandTokens(pattern)
	switch anchor {
	case anchorPrefix:
		body = "^(?:" + body + ")"
	case anchorFull:
		body = "^(?:" + body + ")$"
	}
	if strings.Contains(flags, "i") {
		body = "(?i)" + body
	}
	compiled, err := regexp.Compile(body)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid pattern (%w)", where, err)
	}
	return compiled, nil
}

// expandReplacement substitutes $1–$9 (and $$) in a mask replacement template.
// Go's own Expand syntax differs, so the substitution is done by hand to keep
// pack templates identical across engines.
func expandReplacement(template string, groups []string) string {
	var out strings.Builder
	for i := 0; i < len(template); i++ {
		ch := template[i]
		if ch == '$' && i+1 < len(template) {
			next := template[i+1]
			if next == '$' {
				out.WriteByte('$')
				i++
				continue
			}
			if next >= '1' && next <= '9' {
				index := int(next - '0')
				if index < len(groups) {
					out.WriteString(groups[index])
				}
				i++
				continue
			}
		}
		out.WriteByte(ch)
	}
	return out.String()
}

func stringField(spec map[string]interface{}, name string) string {
	if value, ok := spec[name].(string); ok {
		return value
	}
	return ""
}

func intField(spec map[string]interface{}, name string, fallback int) int {
	if value, ok := spec[name].(float64); ok {
		return int(value)
	}
	return fallback
}

func floatField(spec map[string]interface{}, name string, fallback float64) float64 {
	if value, ok := spec[name].(float64); ok {
		return value
	}
	return fallback
}

func buildMask(spec map[string]interface{}, where string) (func(string) string, error) {
	switch stringField(spec, "type") {
	case "fixed":
		text := stringField(spec, "text")
		return func(string) string { return text }, nil

	case "keepPrefix":
		n := intField(spec, "n", 0)
		return func(value string) string {
			runes := []rune(value)
			if len(runes) <= n {
				return "***"
			}
			return string(runes[:n]) + "***"
		}, nil

	case "keepLast":
		n := intField(spec, "n", 0)
		return func(value string) string {
			d := digitsOf(value)
			tail := d
			if len(d) > n {
				tail = d[len(d)-n:]
			}
			groups := 0
			if len(d) > n {
				groups = (len(d) - n + 3) / 4
			}
			return strings.TrimSpace(strings.Repeat("**** ", groups) + tail)
		}, nil

	case "keepThroughSeparator":
		separator := stringField(spec, "separator")
		count := intField(spec, "count", 1)
		return func(value string) string {
			index, from := -1, 0
			for n := 0; n < count; n++ {
				offset := strings.Index(value[from:], separator)
				if offset < 0 {
					return "***"
				}
				index = from + offset
				from = index + len(separator)
			}
			return value[:index+len(separator)] + "***"
		}, nil

	case "replace":
		re, err := compilePattern(stringField(spec, "pattern"), stringField(spec, "flags"), where+" mask", false, anchorFull)
		if err != nil {
			return nil, err
		}
		replacement := stringField(spec, "replacement")
		return func(value string) string {
			groups := re.FindStringSubmatch(value)
			if groups == nil {
				return value
			}
			return expandReplacement(replacement, groups)
		}, nil
	}
	return nil, fmt.Errorf("%s: unknown mask type %q", where, stringField(spec, "type"))
}

func buildValidator(spec map[string]interface{}, where string) (func(string) bool, error) {
	name := stringField(spec, "name")
	switch name {
	case "normalized_match":
		var strip *regexp.Regexp
		if raw := stringField(spec, "strip"); raw != "" {
			compiled, err := compilePattern(raw, "", where+" validator strip", false, anchorNone)
			if err != nil {
				return nil, err
			}
			strip = compiled
		}
		target, err := compilePattern(stringField(spec, "pattern"), "", where+" validator", false, anchorFull)
		if err != nil {
			return nil, err
		}
		return func(value string) bool {
			candidate := value
			if strip != nil {
				candidate = strip.ReplaceAllString(candidate, "")
			}
			return target.MatchString(candidate)
		}, nil

	case "luhn":
		min := intField(spec, "minDigits", 2)
		max := intField(spec, "maxDigits", 0)
		return func(value string) bool { return Luhn(value, min, max) }, nil

	case "entropy":
		min := floatField(spec, "min", 0)
		return func(value string) bool { return ShannonEntropy(value) >= min }, nil
	}

	if validator, ok := namedValidators[name]; ok {
		return validator, nil
	}
	return nil, fmt.Errorf("%s: unknown validator %q; refusing to load a pack whose checks this engine cannot perform", where, name)
}

func boundaryFor(name, where string) (*byteSet, error) {
	if name == "" {
		return nil, nil
	}
	members, ok := boundarySets[name]
	if !ok {
		return nil, fmt.Errorf("%s: unknown boundary class %q", where, name)
	}
	return newByteSet(members), nil
}

func compileDetector(doc packDetectorDoc) (*Detector, error) {
	where := fmt.Sprintf("detector %q", doc.ID)
	if doc.ID == "" || doc.Label == "" || doc.Why == "" || doc.Pattern == "" || doc.Mask == nil {
		return nil, fmt.Errorf("%s: missing a required field", where)
	}
	switch doc.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return nil, fmt.Errorf("%s: risk must be low, medium, high or critical", where)
	}
	if doc.Confidence < 0 || doc.Confidence > 1 {
		return nil, fmt.Errorf("%s: confidence must be between 0 and 1", where)
	}
	if doc.Flags != "" && doc.Flags != "i" {
		return nil, fmt.Errorf("%s: only the 'i' flag is portable", where)
	}

	regex, err := compilePattern(doc.Pattern, doc.Flags, where, true, anchorNone)
	if err != nil {
		return nil, err
	}
	if regex.MatchString("") {
		return nil, fmt.Errorf("%s: pattern matches the empty string", where)
	}
	if doc.Capture > regex.NumSubexp() {
		return nil, fmt.Errorf("%s: capture group %d does not exist", where, doc.Capture)
	}

	detector := &Detector{
		ID:         doc.ID,
		Label:      doc.Label,
		Why:        doc.Why,
		Risk:       doc.Risk,
		Confidence: doc.Confidence,
		Priority:   doc.Priority,
		Default:    doc.Default,
		Tags:       doc.Tags,
		Refine:     doc.Refine,
		regex:      regex,
		capture:    doc.Capture,
		ctxWindow:  80,
	}

	for _, literal := range doc.Prefilter {
		detector.Prefilter = append(detector.Prefilter, strings.ToLower(literal))
	}

	if doc.Boundary != nil {
		if detector.before, err = boundaryFor(doc.Boundary.Before, where); err != nil {
			return nil, err
		}
		if detector.after, err = boundaryFor(doc.Boundary.After, where); err != nil {
			return nil, err
		}
	}

	for _, raw := range doc.Reject {
		compiled, err := compilePattern(raw, doc.Flags, where+" reject", false, anchorPrefix)
		if err != nil {
			return nil, err
		}
		detector.reject = append(detector.reject, compiled)
	}

	for _, raw := range doc.Validators {
		validator, err := buildValidator(raw, where)
		if err != nil {
			return nil, err
		}
		detector.validators = append(detector.validators, validator)
	}

	if detector.mask, err = buildMask(doc.Mask, where); err != nil {
		return nil, err
	}

	if doc.Context != nil {
		if doc.Context.Window > 0 {
			detector.ctxWindow = doc.Context.Window
		}
		if doc.Context.Positive != "" {
			if detector.ctxPositive, err = compilePattern(doc.Context.Positive, "i", where+" context", false, anchorNone); err != nil {
				return nil, err
			}
		}
		if doc.Context.Negative != "" {
			if detector.ctxNegative, err = compilePattern(doc.Context.Negative, "i", where+" context", false, anchorNone); err != nil {
				return nil, err
			}
		}
	}

	return detector, nil
}

// LoadPack compiles an FRS-1 pack document.
func LoadPack(data []byte) (*Pack, error) {
	var doc packDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("flareredact: pack is not valid JSON: %w", err)
	}
	if doc.Spec != SpecRevision {
		return nil, fmt.Errorf("flareredact: unsupported pack revision %q; this engine implements %s", doc.Spec, SpecRevision)
	}
	if len(doc.Detectors) == 0 {
		return nil, fmt.Errorf("flareredact: a pack must declare at least one detector")
	}

	pack := &Pack{
		ID:      doc.ID,
		Version: doc.Version,
		Title:   doc.Title,
		byID:    make(map[string]*Detector, len(doc.Detectors)),
	}
	if pack.Title == "" {
		pack.Title = pack.ID
	}
	for _, detectorDoc := range doc.Detectors {
		detector, err := compileDetector(detectorDoc)
		if err != nil {
			return nil, err
		}
		if _, exists := pack.byID[detector.ID]; exists {
			return nil, fmt.Errorf("flareredact: duplicate detector id %q", detector.ID)
		}
		pack.byID[detector.ID] = detector
		pack.Detectors = append(pack.Detectors, detector)
	}
	if doc.ConfidenceModel != nil {
		model, err := newConfidenceModel(
			doc.ConfidenceModel.Version,
			doc.ConfidenceModel.Features,
			doc.ConfidenceModel.Weights,
			doc.ConfidenceModel.Bias,
		)
		if err != nil {
			return nil, err
		}
		pack.Model = model
	}
	return pack, nil
}

var (
	corePackOnce sync.Once
	corePack     *Pack
	corePackErr  error
)

// CorePack returns the bundled flare-redact/core pack, compiled once per process.
func CorePack() (*Pack, error) {
	corePackOnce.Do(func() {
		corePack, corePackErr = LoadPack(corePackJSON)
	})
	return corePack, corePackErr
}

// MustCorePack is CorePack for package-level initialisation. It panics if the
// embedded pack is unusable, which can only happen if the build is corrupt.
func MustCorePack() *Pack {
	pack, err := CorePack()
	if err != nil {
		panic(err)
	}
	return pack
}
