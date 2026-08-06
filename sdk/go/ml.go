package flareredact

import (
	"fmt"
	"math"
	"regexp"
)

// The learned secret-confidence classifier.
//
// Pattern-only detection over-fires on high-entropy text: a git SHA, a UUID, a
// content digest and an API key all look alike to a character-class matcher.
// This is a 14-feature logistic regression that scores how likely a match is a
// real secret, so RefineConfidence can push benign look-alikes below a
// threshold instead of masking them.
//
// The weights ship inside the detector pack, which keeps scoring dependency
// free, synchronous and identical across languages. Inference is one feature
// pass and a dot product.

// featureNames lists the features in the exact order extractFeatures returns
// them. A pack whose model does not match this layout is rejected at load time.
var featureNames = [...]string{
	"log2Len", "entropy", "fracLower", "fracUpper", "fracDigit", "fracSymbol",
	"fracHex", "vowelFrac", "classTransitionRate", "hasMixedClasses",
	"maxRunFrac", "structuredHexId", "ctxSecret", "ctxBenign",
}

// ConfidenceModel holds logistic-regression weights loaded from a pack.
type ConfidenceModel struct {
	Version  int
	Features []string
	Weights  []float64
	Bias     float64
}

func newConfidenceModel(version int, features []string, weights []float64, bias float64) (*ConfidenceModel, error) {
	if len(weights) != len(features) {
		return nil, fmt.Errorf("flareredact: confidence model has %d weights for %d features", len(weights), len(features))
	}
	if len(features) != len(featureNames) {
		return nil, fmt.Errorf("flareredact: confidence model declares %d features, this engine implements %d", len(features), len(featureNames))
	}
	for i, name := range features {
		if name != featureNames[i] {
			return nil, fmt.Errorf("flareredact: confidence model feature %d is %q, expected %q", i, name, featureNames[i])
		}
	}
	return &ConfidenceModel{Version: version, Features: features, Weights: weights, Bias: bias}, nil
}

var (
	secretContext = regexp.MustCompile(`(?i)\b(secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)\b`)
	benignContext = regexp.MustCompile(`(?i)\b(uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id|content[_-]?id|version|colou?r|slug|filename)\b`)
	structuredHex = regexp.MustCompile(`(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)
)

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}

// extractFeatures builds the fixed-length vector for value, informed by nearby
// context text.
func extractFeatures(value, context string) []float64 {
	runes := []rune(value)
	length := len(runes)
	if length == 0 {
		length = 1
	}
	var lower, upper, digit, symbol, hexish, vowel, letters int
	transitions, run, maxRun, prevClass := 0, 1, 1, -1

	for _, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
			lower++
			letters++
		case r >= 'A' && r <= 'Z':
			upper++
			letters++
		case r >= '0' && r <= '9':
			digit++
		default:
			symbol++
		}
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			hexish++
		}
		if isVowel(r) {
			vowel++
		}
		class := 2
		switch {
		case r >= '0' && r <= '9':
			class = 1
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			class = 0
		}
		if prevClass == -1 {
			prevClass = class
		} else {
			if class != prevClass {
				transitions++
				run = 1
			} else {
				run++
			}
			if run > maxRun {
				maxRun = run
			}
			prevClass = class
		}
	}

	total := float64(length)
	vowelFrac := 0.0
	if letters > 0 {
		vowelFrac = float64(vowel) / float64(letters)
	}
	transitionRate := 0.0
	if length > 1 {
		transitionRate = float64(transitions) / float64(length-1)
	}
	mixed := 0.0
	if lower > 0 && upper > 0 && digit > 0 {
		mixed = 1
	}
	boolFeature := func(ok bool) float64 {
		if ok {
			return 1
		}
		return 0
	}

	return []float64{
		math.Log2(total),
		ShannonEntropy(value),
		float64(lower) / total,
		float64(upper) / total,
		float64(digit) / total,
		float64(symbol) / total,
		float64(hexish) / total,
		vowelFrac,
		transitionRate,
		mixed,
		float64(maxRun) / total,
		boolFeature(structuredHex.MatchString(value)),
		boolFeature(secretContext.MatchString(context)),
		boolFeature(benignContext.MatchString(context)),
	}
}

func sigmoid(z float64) float64 {
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	e := math.Exp(z)
	return e / (1 + e)
}

// SecretProbability returns the probability in [0, 1] that value is a real
// secret rather than a benign high-entropy look-alike.
func SecretProbability(value, context string, model *ConfidenceModel) float64 {
	features := extractFeatures(value, context)
	z := model.Bias
	for i, weight := range model.Weights {
		z += weight * features[i]
	}
	return sigmoid(z)
}
