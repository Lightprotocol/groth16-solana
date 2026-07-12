//! Guards the CU table in the crate docs (src/lib.rs, rendered into
//! README.md by cargo-rdme) against drift: `just bench` regenerates
//! BENCHMARKS.md and CI fails on an uncommitted diff, so a CU change
//! that lands there must also update the doc table. On failure, edit
//! the Benchmarks table in src/lib.rs and run `just readme`.

const BENCHMARKS: &str = include_str!("../BENCHMARKS.md");
const LIB_RS: &str = include_str!("../src/lib.rs");

/// (mode, public inputs, total CU) triples parsed from BENCHMARKS.md:
/// each "## <i>. <mode> - <n> public input(s)" section is followed by a
/// table whose data row is "| `<fn>` | <total> | <net> |".
fn benchmark_totals() -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    let mut section: Option<(String, usize)> = None;
    for line in BENCHMARKS.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            let Some((_, title)) = rest.split_once(". ") else {
                continue;
            };
            let Some((mode, inputs)) = title.split_once(" - ") else {
                continue;
            };
            let n = inputs
                .split_whitespace()
                .next()
                .and_then(|word| word.parse().ok())
                .unwrap_or_else(|| panic!("no public input count in heading {line:?}"));
            section = Some((mode.to_string(), n));
        } else if line.starts_with("| `") {
            let (mode, n) = section
                .take()
                .unwrap_or_else(|| panic!("data row without a section heading: {line:?}"));
            let total = line
                .split('|')
                .nth(2)
                .map(str::trim)
                .unwrap_or_else(|| panic!("no total CU column in {line:?}"));
            out.push((mode, n, total.to_string()));
        }
    }
    out
}

#[test]
fn crate_docs_cu_table_matches_benchmarks() {
    let totals = benchmark_totals();
    let plain: Vec<_> = totals.iter().filter(|(m, _, _)| m == "Groth16").collect();
    let bsb22: Vec<_> = totals
        .iter()
        .filter(|(m, _, _)| m == "Groth16-bsb22")
        .collect();
    assert_eq!(plain.len(), 4, "expected 4 plain sections, got {totals:?}");
    assert_eq!(bsb22.len(), 4, "expected 4 bsb22 sections, got {totals:?}");

    for ((_, n, plain_cu), (_, bsb22_n, bsb22_cu)) in plain.iter().zip(bsb22.iter()) {
        assert_eq!(n, bsb22_n, "plain/bsb22 section order mismatch");
        let row = format!("//! | {n} | {plain_cu} | {bsb22_cu} |");
        assert!(
            LIB_RS.contains(&row),
            "src/lib.rs CU table is missing the row {row:?}; update the \
             Benchmarks table in the crate docs and run `just readme`"
        );
    }

    // The crate-docs intro quotes the 1-input and 8-input endpoints as
    // "<min>–<max> CU" ranges for both modes.
    for group in [&plain, &bsb22] {
        let (_, _, min) = group.first().expect("nonempty group");
        let (_, _, max) = group.last().expect("nonempty group");
        let range = format!("{min}–{max} CU");
        assert!(
            LIB_RS.contains(&range),
            "src/lib.rs intro is missing the CU range {range:?}; update \
             the crate docs and run `just readme`"
        );
    }
}
