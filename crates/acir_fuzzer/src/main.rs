mod artifact;
mod bb_oracle;
mod evaluator;
mod fuzzer;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::artifact::{load_artifact, load_witness_map};
use crate::bb_oracle::BbOracle;
use crate::fuzzer::{FuzzerConfig, run_fuzz_suite};

#[derive(Debug, Parser)]
#[command(
    name = "acir_fuzzer",
    about = "Stage 1 ACIR single-wire and relational witness fuzzer with Barretenberg oracle"
)]
struct Cli {
    #[arg(long)]
    artifact: PathBuf,
    #[arg(long)]
    witness: PathBuf,
    #[arg(long)]
    vk: Option<PathBuf>,
    #[arg(long)]
    report: PathBuf,
    #[arg(long, default_value_t = false)]
    allow_dummy_unused: bool,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    #[arg(long, default_value_t = 2000)]
    random_pairs: usize,
}

fn run(cli: Cli) -> Result<bool> {
    let artifact = load_artifact(&cli.artifact)?;
    let baseline = load_witness_map(&cli.witness)?;
    let oracle = BbOracle::new(cli.artifact.clone(), cli.vk.clone())?;

    let cfg = FuzzerConfig {
        allow_dummy_unused: cli.allow_dummy_unused,
        seed: cli.seed,
        random_pairs: cli.random_pairs,
    };

    let report = run_fuzz_suite(&artifact, &baseline, Some(&oracle), &cfg)?;

    if let Some(parent) = cli.report.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_string_pretty(&report).context("failed to serialize JSON report")?;
    fs::write(&cli.report, json)
        .with_context(|| format!("failed to write report to {}", cli.report.display()))?;

    println!(
        "acir_fuzzer summary: wires={}, single_wire_checked={}, relational_checked={}, whitelisted_wires={}, whitelisted_survivors={}, benign_is_zero_inverses={}, benign_is_zero_survivors={}, unexpected_survivors={}, confirmed_bb_exploits={}, elapsed_ms={}",
        report.total_wires,
        report.single_wire_mutations_checked,
        report.relational_probes_checked,
        report.whitelisted_dummy_wires.len(),
        report.whitelisted_survivors,
        report.benign_is_zero_inverses.len(),
        report.benign_is_zero_survivors,
        report.unexpected_survivors.len(),
        report.confirmed_bb_exploits,
        report.elapsed_ms,
    );

    if !report.unexpected_survivors.is_empty() {
        for finding in &report.unexpected_survivors {
            eprintln!(
                "UNEXPECTED SURVIVOR [{}] {}: wires={:?}, bb={:?}",
                finding.stage, finding.probe, finding.wires, finding.bb_confirmation
            );
        }
    }

    Ok(report.unexpected_survivors.is_empty() && report.confirmed_bb_exploits == 0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("acir_fuzzer error: {err:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use acir::circuit::opcodes::BlackBoxFuncCall;
    use acir::circuit::opcodes::FunctionInput;
    use acir::circuit::{Circuit, Opcode, Program, PublicInputs};
    use acir::native_types::{Expression, Witness, WitnessMap};
    use acir::{AcirField, FieldElement};
    use acvm_blackbox_solver::BlackBoxFunctionSolver;
    use bn254_blackbox_solver::Bn254BlackBoxSolver;

    use crate::artifact::LoadedArtifact;
    use crate::fuzzer::{FuzzerConfig, run_fuzz_suite};

    fn make_synthetic_artifact(circuit: Circuit<FieldElement>) -> LoadedArtifact {
        LoadedArtifact {
            program: Program {
                functions: vec![circuit],
                unconstrained_functions: vec![],
            },
            abi_witnesses: vec![],
            label_to_witness: BTreeMap::new(),
            witness_to_label: BTreeMap::new(),
        }
    }

    #[test]
    fn test_canary_catches_unconstrained_wire() {
        // Circuit enforces w0 - w1 == 0, while w2 is an unconstrained dead wire in WitnessMap.
        let expr = Expression {
            mul_terms: vec![],
            linear_combinations: vec![
                (FieldElement::one(), Witness(0)),
                (-FieldElement::one(), Witness(1)),
            ],
            q_c: FieldElement::zero(),
        };
        let circuit = Circuit {
            function_name: "canary_dead_wire".to_string(),
            opcodes: vec![Opcode::AssertZero(expr)],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            public_parameters: PublicInputs(BTreeSet::from([Witness(0)])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = make_synthetic_artifact(circuit);
        let witness = WitnessMap::from(BTreeMap::from([
            (Witness(0), FieldElement::from(7u64)),
            (Witness(1), FieldElement::from(7u64)),
            (Witness(2), FieldElement::from(99u64)),
        ]));
        let cfg = FuzzerConfig {
            allow_dummy_unused: false,
            seed: 42,
            random_pairs: 200,
        };
        let report = run_fuzz_suite(&artifact, &witness, None, &cfg).unwrap();
        assert!(
            report
                .unexpected_survivors
                .iter()
                .any(|f| f.stage == "single_wire" && f.wires.iter().any(|w| w == "w2")),
            "expected w2 dead wire to be caught, got: {:?}",
            report.unexpected_survivors
        );
    }

    #[test]
    fn test_canary_catches_missing_range_wrap() {
        // Circuit enforces w0 + w1 - w2 == 0 WITHOUT RANGE checks.
        // Relational probe mutates w0 = p - 1 and w1 += 1, keeping sum invariant!
        let expr = Expression {
            mul_terms: vec![],
            linear_combinations: vec![
                (FieldElement::one(), Witness(0)),
                (FieldElement::one(), Witness(1)),
                (-FieldElement::one(), Witness(2)),
            ],
            q_c: FieldElement::zero(),
        };
        let circuit = Circuit {
            function_name: "canary_missing_range".to_string(),
            opcodes: vec![Opcode::AssertZero(expr)],
            private_parameters: BTreeSet::from([Witness(0), Witness(1)]),
            public_parameters: PublicInputs(BTreeSet::from([Witness(2)])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = make_synthetic_artifact(circuit);
        let witness = WitnessMap::from(BTreeMap::from([
            (Witness(0), FieldElement::from(10u64)),
            (Witness(1), FieldElement::from(20u64)),
            (Witness(2), FieldElement::from(30u64)),
        ]));
        let cfg = FuzzerConfig {
            allow_dummy_unused: false,
            seed: 42,
            random_pairs: 200,
        };
        let report = run_fuzz_suite(&artifact, &witness, None, &cfg).unwrap();
        assert!(
            report
                .unexpected_survivors
                .iter()
                .any(|f| f.stage.starts_with("relational")),
            "expected relational wrap-around to be caught, got: {:?}",
            report.unexpected_survivors
        );
    }

    #[test]
    fn test_sound_tiny_circuit_passes() {
        // Sound tiny circuit: w0, w1, w2 in [0, 2^64), w0 + w1 == w2, and Poseidon2(w0, w1, w2, 0) == (w3, w4, w5, w6)
        let solver = Bn254BlackBoxSolver;
        let w0_val = FieldElement::from(10u64);
        let w1_val = FieldElement::from(20u64);
        let w2_val = FieldElement::from(30u64);
        let p2_out = solver
            .poseidon2_permutation(&[w0_val, w1_val, w2_val, FieldElement::zero()])
            .unwrap();

        let sum_expr = Expression {
            mul_terms: vec![],
            linear_combinations: vec![
                (FieldElement::one(), Witness(0)),
                (FieldElement::one(), Witness(1)),
                (-FieldElement::one(), Witness(2)),
            ],
            q_c: FieldElement::zero(),
        };
        let circuit = Circuit {
            function_name: "sound_tiny".to_string(),
            opcodes: vec![
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                    input: FunctionInput::Witness(Witness(0)),
                    num_bits: 64,
                }),
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                    input: FunctionInput::Witness(Witness(1)),
                    num_bits: 64,
                }),
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                    input: FunctionInput::Witness(Witness(2)),
                    num_bits: 64,
                }),
                Opcode::AssertZero(sum_expr),
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation {
                    inputs: vec![
                        FunctionInput::Witness(Witness(0)),
                        FunctionInput::Witness(Witness(1)),
                        FunctionInput::Witness(Witness(2)),
                        FunctionInput::Constant(FieldElement::zero()),
                    ],
                    outputs: vec![Witness(3), Witness(4), Witness(5), Witness(6)],
                }),
            ],
            private_parameters: BTreeSet::from([Witness(0), Witness(1)]),
            public_parameters: PublicInputs(BTreeSet::from([Witness(2), Witness(3), Witness(4), Witness(5), Witness(6)])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = make_synthetic_artifact(circuit);
        let witness = WitnessMap::from(BTreeMap::from([
            (Witness(0), w0_val),
            (Witness(1), w1_val),
            (Witness(2), w2_val),
            (Witness(3), p2_out[0]),
            (Witness(4), p2_out[1]),
            (Witness(5), p2_out[2]),
            (Witness(6), p2_out[3]),
        ]));
        let cfg = FuzzerConfig {
            allow_dummy_unused: false,
            seed: 42,
            random_pairs: 500,
        };
        let report = run_fuzz_suite(&artifact, &witness, None, &cfg).unwrap();
        assert!(
            report.unexpected_survivors.is_empty(),
            "expected zero survivors on sound tiny circuit, got: {:?}",
            report.unexpected_survivors
        );
    }

    #[test]
    fn test_benign_is_zero_inverse_classified() {
        // Sound 2-constraint IsZero(0) gadget: w0 * w2 + w1 - 1 == 0 and w0 * w1 == 0
        // with w0 = private 0, w1 = public 1, w2 = internal inv = 0.
        let e1 = Expression {
            mul_terms: vec![(FieldElement::one(), Witness(0), Witness(2))],
            linear_combinations: vec![(FieldElement::one(), Witness(1))],
            q_c: -FieldElement::one(),
        };
        let e2 = Expression {
            mul_terms: vec![(FieldElement::one(), Witness(0), Witness(1))],
            linear_combinations: vec![],
            q_c: FieldElement::zero(),
        };
        let circuit = Circuit {
            function_name: "sound_is_zero".to_string(),
            opcodes: vec![Opcode::AssertZero(e1), Opcode::AssertZero(e2)],
            private_parameters: BTreeSet::from([Witness(0)]),
            public_parameters: PublicInputs(BTreeSet::from([Witness(1)])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = make_synthetic_artifact(circuit);
        let witness = WitnessMap::from(BTreeMap::from([
            (Witness(0), FieldElement::zero()),
            (Witness(1), FieldElement::one()),
            (Witness(2), FieldElement::zero()),
        ]));
        let cfg = FuzzerConfig {
            allow_dummy_unused: false,
            seed: 42,
            random_pairs: 200,
        };
        let report = run_fuzz_suite(&artifact, &witness, None, &cfg).unwrap();
        assert!(
            report.unexpected_survivors.is_empty(),
            "expected zero unexpected survivors, got: {:?}",
            report.unexpected_survivors
        );
        assert!(
            report.benign_is_zero_inverses.iter().any(|w| w == "w2"),
            "expected w2 in benign_is_zero_inverses, got: {:?}",
            report.benign_is_zero_inverses
        );
        assert!(report.benign_is_zero_survivors > 0);
    }

    #[test]
    fn test_canary_broken_is_zero_still_caught() {
        // Broken IsZero gadget missing companion w0 * w1 == 0 constraint -> w2 MUST NOT be benign!
        let e1 = Expression {
            mul_terms: vec![(FieldElement::one(), Witness(0), Witness(2))],
            linear_combinations: vec![(FieldElement::one(), Witness(1))],
            q_c: -FieldElement::one(),
        };
        let circuit = Circuit {
            function_name: "broken_is_zero".to_string(),
            opcodes: vec![Opcode::AssertZero(e1)],
            private_parameters: BTreeSet::from([Witness(0)]),
            public_parameters: PublicInputs(BTreeSet::from([Witness(1)])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = make_synthetic_artifact(circuit);
        let witness = WitnessMap::from(BTreeMap::from([
            (Witness(0), FieldElement::zero()),
            (Witness(1), FieldElement::one()),
            (Witness(2), FieldElement::zero()),
        ]));
        let cfg = FuzzerConfig {
            allow_dummy_unused: false,
            seed: 42,
            random_pairs: 200,
        };
        let report = run_fuzz_suite(&artifact, &witness, None, &cfg).unwrap();
        assert!(
            !report.benign_is_zero_inverses.iter().any(|w| w == "w2"),
            "broken IsZero must NOT classify w2 as benign"
        );
        assert!(
            report
                .unexpected_survivors
                .iter()
                .any(|f| f.stage == "single_wire" && f.wires.iter().any(|w| w == "w2")),
            "expected broken IsZero w2 to be caught as unexpected survivor"
        );
    }

    #[test]
    fn test_public_input_inverse_not_falsely_flagged() {
        // Public w0 = 7, private w1 = 1/7 with w0 * w1 - 1 == 0, plus private w2 = 7 with w2 - w0 == 0.
        // Holding public inputs fixed in relational_random prevents falsely flagging (-w0, -w1).
        let inv_expr = Expression {
            mul_terms: vec![(FieldElement::one(), Witness(0), Witness(1))],
            linear_combinations: vec![],
            q_c: -FieldElement::one(),
        };
        let eq_expr = Expression {
            mul_terms: vec![],
            linear_combinations: vec![
                (FieldElement::one(), Witness(2)),
                (-FieldElement::one(), Witness(0)),
            ],
            q_c: FieldElement::zero(),
        };
        let circuit = Circuit {
            function_name: "pub_inv".to_string(),
            opcodes: vec![Opcode::AssertZero(inv_expr), Opcode::AssertZero(eq_expr)],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            public_parameters: PublicInputs(BTreeSet::from([Witness(0)])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = make_synthetic_artifact(circuit);
        let w0 = FieldElement::from(7u64);
        let w1 = w0.inverse();
        let witness = WitnessMap::from(BTreeMap::from([
            (Witness(0), w0),
            (Witness(1), w1),
            (Witness(2), w0),
        ]));
        let cfg = FuzzerConfig {
            allow_dummy_unused: false,
            seed: 42,
            random_pairs: 500,
        };
        let report = run_fuzz_suite(&artifact, &witness, None, &cfg).unwrap();
        assert!(
            report.unexpected_survivors.is_empty(),
            "expected zero unexpected survivors with public input fixed, got: {:?}",
            report.unexpected_survivors
        );
    }
}

