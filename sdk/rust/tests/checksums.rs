//! Known-answer tests for the national ID validators added with 14 more
//! countries. Every valid sample was generated for these tests and cross-checked
//! with an independent implementation; none belongs to a person. The same table
//! runs in the JavaScript, Python and Go test suites.

use flare_redact::checksums::named;

type KnownAnswer = (&'static str, &'static [&'static str], &'static [&'static str]);

const KNOWN_ANSWERS: &[KnownAnswer] = &[
    (
        "cnp",
        &["1850101401238", "5050505123453"],
        &["1850101401239", "1851301401236", "0850101401238"],
    ),
    (
        "personnummer",
        &["850709-1232", "200505054569", "850769-1239"],
        &["850709-1233", "851309-1234", "170505054569"],
    ),
    (
        "hetu",
        &["010185-123B", "150605A456H"],
        &["010185-123C", "320185-123B", "010185-001K", "010185-123b"],
    ),
    (
        "fodselsnummer",
        &["01018512366", "010185 12447", "41018510187", "01458512309"],
        &["01018512367", "32018512318"],
    ),
    (
        "be_national_number",
        &["85.01.01-123.87", "05050500186", "85210112333"],
        &["85010112388", "85130112374"],
    ),
    (
        "pt_nif",
        &["123456789", "234 567 899", "451234561"],
        &["123456788", "512345678"],
    ),
    (
        "za_id",
        &["8501015123085", "0505056000183"],
        &["8501015123086", "8513015123080", "8501015123383"],
    ),
    (
        "curp",
        &["ABCD850101HDFBCD00", "WXYZ050505MNLRSTA4"],
        &["ABCD850101HDFBCD01", "ABCD851301HDFBCD06", "ABCD850101HXXBCD00"],
    ),
    (
        "rut",
        &["12.345.678-5", "7.654.321-6", "10000013-K", "10000013-k"],
        &["12.345.678-6", "10000013-0"],
    ),
    (
        "cuit",
        &["20-12345678-6", "27876543219"],
        &["20-12345678-7", "30123456781"],
    ),
    (
        "nric",
        &["S1234567D", "T1234567J", "F1234567N", "G1234567X"],
        &["S1234567A", "G1234567N", "s1234567d"],
    ),
    (
        "amka",
        &["01018512341", "31120543215"],
        &["01018512342", "32018512346"],
    ),
    (
        "uk_nino",
        &["AB 12 34 56 C", "AB123456C"],
        &["QQ 12 34 56 C", "GB 12 34 56 A", "AO 12 34 56 A", "AB 12 34 56 E"],
    ),
];

#[test]
fn national_id_validators_match_known_answers() {
    for (name, valid, invalid) in KNOWN_ANSWERS {
        let check = named(name).unwrap_or_else(|| panic!("validator {name} is not registered"));
        for value in *valid {
            assert!(check(value), "{name}: expected {value:?} to be valid");
        }
        for value in *invalid {
            assert!(!check(value), "{name}: expected {value:?} to be invalid");
        }
    }
}
