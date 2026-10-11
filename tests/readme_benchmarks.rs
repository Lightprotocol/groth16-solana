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
    let modes = [
        "Groth16",
        "Groth16-bsb22",
        "Groth16-bsb22-opt",
        "Groth16-bsb22-opt-hint",
        "Groth16-bsb22-opt-cached",
        "Groth16-bsb22-opt-hint-cached",
    ];
    let groups: Vec<Vec<_>> = modes
        .iter()
        .map(|mode| {
            let group: Vec<_> = totals.iter().filter(|(m, _, _)| m == mode).collect();
            assert_eq!(
                group.len(),
                4,
                "expected 4 sections for {mode}, got {totals:?}"
            );
            group
        })
        .collect();
    for n in [1, 2, 4, 8] {
        let mut row = format!("//! | {n} |");
        for group in &groups {
            let (_, _, cu) = group.iter().find(|(_, inputs, _)| *inputs == n).unwrap();
            row.push_str(&format!(" {cu} |"));
        }
        assert!(
            LIB_RS.contains(&row),
            "src/lib.rs CU table is missing {row:?}; update it and run just readme"
        );
    }
    // The introduction reports ordinary, default BSB22, optimized and fully accelerated ranges.
    for i in [0, 1, 2, 5] {
        let group = groups.get(i).unwrap();
        let (_, _, min) = group.first().unwrap();
        let (_, _, max) = group.last().unwrap();
        let range = format!("{min}–{max} CU");
        assert!(
            LIB_RS.contains(&range),
            "src/lib.rs intro is missing {range:?}"
        );
    }
}
