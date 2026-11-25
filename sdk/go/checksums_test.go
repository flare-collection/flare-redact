package flareredact

import "testing"

// Known-answer tests for the national ID validators added with 14 more
// countries. Every valid sample was generated for these tests and cross-checked
// with an independent implementation; none belongs to a person. The same table
// runs in the other engines' test suites.
var nationalIDKnownAnswers = []struct {
	name    string
	valid   []string
	invalid []string
}{
	{"cnp", []string{"1850101401238", "5050505123453"}, []string{"1850101401239", "1851301401236", "0850101401238"}},
	{"personnummer", []string{"850709-1232", "200505054569", "850769-1239"}, []string{"850709-1233", "851309-1234", "170505054569"}},
	{"hetu", []string{"010185-123B", "150605A456H"}, []string{"010185-123C", "320185-123B", "010185-001K", "010185-123b"}},
	{"fodselsnummer", []string{"01018512366", "010185 12447", "41018510187", "01458512309"}, []string{"01018512367", "32018512318"}},
	{"be_national_number", []string{"85.01.01-123.87", "05050500186", "85210112333"}, []string{"85010112388", "85130112374"}},
	{"pt_nif", []string{"123456789", "234 567 899", "451234561"}, []string{"123456788", "512345678"}},
	{"za_id", []string{"8501015123085", "0505056000183"}, []string{"8501015123086", "8513015123080", "8501015123383"}},
	{"curp", []string{"ABCD850101HDFBCD00", "WXYZ050505MNLRSTA4"}, []string{"ABCD850101HDFBCD01", "ABCD851301HDFBCD06", "ABCD850101HXXBCD00"}},
	{"rut", []string{"12.345.678-5", "7.654.321-6", "10000013-K", "10000013-k"}, []string{"12.345.678-6", "10000013-0"}},
	{"cuit", []string{"20-12345678-6", "27876543219"}, []string{"20-12345678-7", "30123456781"}},
	{"nric", []string{"S1234567D", "T1234567J", "F1234567N", "G1234567X"}, []string{"S1234567A", "G1234567N", "s1234567d"}},
	{"amka", []string{"01018512341", "31120543215"}, []string{"01018512342", "32018512346"}},
	{"uk_nino", []string{"AB 12 34 56 C", "AB123456C"}, []string{"QQ 12 34 56 C", "GB 12 34 56 A", "AO 12 34 56 A", "AB 12 34 56 E"}},
}

func TestNationalIDValidatorsKnownAnswers(t *testing.T) {
	for _, c := range nationalIDKnownAnswers {
		check, ok := namedValidators[c.name]
		if !ok {
			t.Fatalf("validator %q is not registered", c.name)
		}
		for _, value := range c.valid {
			if !check(value) {
				t.Errorf("%s: expected %q to be valid", c.name, value)
			}
		}
		for _, value := range c.invalid {
			if check(value) {
				t.Errorf("%s: expected %q to be invalid", c.name, value)
			}
		}
	}
}
