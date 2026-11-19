use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{Circuit, Opcode, Program};
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acir::{AcirField, FieldElement};
use anyhow::{Context, Result, bail};
use base64::Engine;
use num_bigint::BigUint;
use serde::Deserialize;

pub const BN254_FR_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Debug, Deserialize)]
struct NargoArtifactJson {
    abi: AbiJson,
    bytecode: String,
}

#[derive(Debug, Deserialize)]
struct AbiJson {
    parameters: Vec<AbiParam>,
}

#[derive(Debug, Deserialize)]
struct AbiParam {
    name: String,
    visibility: String,
    #[serde(rename = "type")]
    param_type: AbiType,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AbiType {
    Field,
    Boolean,
    Integer {
        #[allow(dead_code)]
        sign: String,
        #[allow(dead_code)]
        width: u32,
    },
    Array {
        length: usize,
        #[serde(rename = "type")]
        elem_type: Box<AbiType>,
    },
    #[serde(rename = "struct")]
    Struct {
        #[allow(dead_code)]
        path: String,
        fields: Vec<AbiStructField>,
    },
    Tuple {
        fields: Vec<AbiType>,
    },
}

#[derive(Debug, Deserialize)]
struct AbiStructField {
    name: String,
    #[serde(rename = "type")]
    field_type: AbiType,
}

/// Decoded Noir ACIR circuit with ABI witness mapping and collected `RANGE` bounds.
pub struct SmtCircuit {
    pub name: String,
    pub circuit: Circuit<FieldElement>,
    pub labels: BTreeMap<String, Witness>,
    pub range_bounds: BTreeMap<Witness, BTreeSet<u32>>,
}

/// Loads a Noir `.json` artifact and extracts its ACIR circuit, ABI labels, and `RANGE` opcodes.
pub fn load_smt_circuit(artifact_path: &Path, name: &str) -> Result<SmtCircuit> {
    let raw = fs::read_to_string(artifact_path)
        .with_context(|| format!("failed to read {}", artifact_path.display()))?;
    let parsed: NargoArtifactJson = serde_json::from_str(&raw)?;
    let bytecode = base64::engine::general_purpose::STANDARD.decode(parsed.bytecode.trim())?;
    let program = Program::<FieldElement>::deserialize_program(&bytecode)?;
    let circuit = program
        .functions
        .first()
        .context("ACIR program has no functions")?
        .clone();

    let mut pub_names = Vec::new();
    let mut priv_names = Vec::new();
    for param in &parsed.abi.parameters {
        let out = if param.visibility == "public" {
            &mut pub_names
        } else {
            &mut priv_names
        };
        flatten_abi(&param.name, &param.param_type, out);
    }

    let pub_ws: Vec<Witness> = circuit.public_parameters.0.iter().copied().collect();
    let priv_ws: Vec<Witness> = circuit.private_parameters.iter().copied().collect();
    if pub_names.len() != pub_ws.len() || priv_names.len() != priv_ws.len() {
        bail!("ABI parameter mismatch in {name}");
    }

    let mut labels = BTreeMap::new();
    for (n, w) in pub_names
        .into_iter()
        .zip(pub_ws)
        .chain(priv_names.into_iter().zip(priv_ws))
    {
        labels.insert(n, w);
    }

    let mut range_bounds: BTreeMap<Witness, BTreeSet<u32>> = BTreeMap::new();
    for op in &circuit.opcodes {
        if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE { input, num_bits }) = op {
            if let FunctionInput::Witness(w) = input {
                range_bounds.entry(*w).or_default().insert(*num_bits);
            }
        }
    }

    Ok(SmtCircuit {
        name: name.to_string(),
        circuit,
        labels,
        range_bounds,
    })
}

pub fn load_witness_map(path: &Path) -> Result<WitnessMap<FieldElement>> {
    let bytes = fs::read(path)?;
    let mut stack = WitnessStack::<FieldElement>::deserialize(&bytes)?;
    Ok(stack.pop().context("empty witness stack")?.witness)
}

fn flatten_abi(prefix: &str, ty: &AbiType, out: &mut Vec<String>) {
    match ty {
        AbiType::Field | AbiType::Boolean | AbiType::Integer { .. } => {
            out.push(prefix.to_string());
        }
        AbiType::Array { length, elem_type } => {
            for i in 0..*length {
                flatten_abi(&format!("{prefix}[{i}]"), elem_type, out);
            }
        }
        AbiType::Struct { fields, .. } => {
            for f in fields {
                flatten_abi(&format!("{prefix}.{}", f.name), &f.field_type, out);
            }
        }
        AbiType::Tuple { fields } => {
            for (i, f) in fields.iter().enumerate() {
                flatten_abi(&format!("{prefix}.{i}"), f, out);
            }
        }
    }
}

pub fn ff_literal(val: FieldElement) -> String {
    let big = BigUint::from_bytes_be(&val.to_be_bytes());
    format!("(as ff{big} F)")
}

/// Builder for SMT-LIB2 finite-field + uninterpreted-function scripts over BN254 `Fr`.
pub struct SmtProgramBuilder {
    wires: BTreeSet<String>,
    msm_arities: BTreeSet<usize>,
    has_poseidon2: bool,
    assertions: Vec<String>,
}

impl SmtProgramBuilder {
    pub fn new() -> Self {
        Self {
            wires: BTreeSet::new(),
            msm_arities: BTreeSet::new(),
            has_poseidon2: false,
            assertions: Vec::new(),
        }
    }

    /// Emits all non-Brillig ACIR opcodes of `circuit` with variable prefix `prefix`.
    /// When `solve_linear` is `true`, linear `AssertZero` definitions are solved into
    /// algebraically equivalent `(= w rhs)` equalities over `F_p` (fast for `unsat`
    /// invariant and 2-copy congruence proofs). When `solve_linear` is `false`,
    /// canonical `(= lhs (as ff0 F))` constraints are emitted (fast for pinned-witness
    /// `sat` non-vacuousness checks).
    pub fn emit_acir_copy(
        &mut self,
        circuit: &Circuit<FieldElement>,
        prefix: &str,
        solve_linear: bool,
    ) -> Result<()> {
        let mut defined: BTreeSet<Witness> = circuit.private_parameters.iter().copied().collect();

        for op in &circuit.opcodes {
            match op {
                Opcode::AssertZero(expr) => {
                    let mut mul_ws = BTreeSet::new();
                    for &(_, a, b) in &expr.mul_terms {
                        mul_ws.insert(a);
                        mul_ws.insert(b);
                        self.wires.insert(format!("{prefix}w{}", a.0));
                        self.wires.insert(format!("{prefix}w{}", b.0));
                    }
                    for &(_, w) in &expr.linear_combinations {
                        self.wires.insert(format!("{prefix}w{}", w.0));
                    }

                    // Solve for the last undefined linear witness appearing once (not in mul_terms)
                    let mut target = None;
                    if solve_linear {
                        for (idx, &(c, w)) in expr.linear_combinations.iter().enumerate() {
                            if !c.is_zero()
                                && !mul_ws.contains(&w)
                                && !defined.contains(&w)
                                && expr
                                    .linear_combinations
                                    .iter()
                                    .filter(|(_, lw)| *lw == w)
                                    .count()
                                    == 1
                            {
                                target = Some((idx, c, w));
                            }
                        }
                    }

                    if let Some((t_idx, c, tw)) = target {
                        defined.insert(tw);
                        let inv_neg_c = -c.inverse();
                        let mut rhs_terms = Vec::new();

                        for &(mc, a, b) in &expr.mul_terms {
                            let scaled = mc * inv_neg_c;
                            if !scaled.is_zero() {
                                rhs_terms.push(format_mul_term(scaled, a, b, prefix));
                            }
                        }
                        for (idx, &(lc, w)) in expr.linear_combinations.iter().enumerate() {
                            if idx == t_idx {
                                continue;
                            }
                            let scaled = lc * inv_neg_c;
                            if !scaled.is_zero() {
                                rhs_terms.push(format_lin_term(scaled, w, prefix));
                            }
                        }
                        let rc = expr.q_c * inv_neg_c;
                        if !rc.is_zero() || rhs_terms.is_empty() {
                            rhs_terms.push(ff_literal(rc));
                        }

                        let rhs = combine_ff_add(&rhs_terms);
                        self.assertions
                            .push(format!("(assert (= {prefix}w{} {rhs}))", tw.0));
                    } else {
                        let mut terms = Vec::new();
                        for &(mc, a, b) in &expr.mul_terms {
                            if !mc.is_zero() {
                                terms.push(format_mul_term(mc, a, b, prefix));
                            }
                        }
                        for &(lc, w) in &expr.linear_combinations {
                            if !lc.is_zero() {
                                terms.push(format_lin_term(lc, w, prefix));
                            }
                        }
                        if !expr.q_c.is_zero() {
                            terms.push(ff_literal(expr.q_c));
                        }
                        if !terms.is_empty() {
                            let lhs = combine_ff_add(&terms);
                            self.assertions.push(format!("(assert (= {lhs} (as ff0 F)))"));
                        }
                    }
                }
                Opcode::BlackBoxFuncCall(call) => match call {
                    BlackBoxFuncCall::RANGE { input, .. } => {
                        if let FunctionInput::Witness(w) = input {
                            self.wires.insert(format!("{prefix}w{}", w.0));
                        }
                    }
                    BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                        self.has_poseidon2 = true;
                        let args: Vec<String> = inputs
                            .iter()
                            .map(|fi| self.format_input(fi, prefix))
                            .collect();
                        for (k, ow) in outputs.iter().enumerate() {
                            self.wires.insert(format!("{prefix}w{}", ow.0));
                            defined.insert(*ow);
                            self.assertions.push(format!(
                                "(assert (= {prefix}w{} (p2_{k} {})))",
                                ow.0,
                                args.join(" ")
                            ));
                        }
                    }
                    BlackBoxFuncCall::MultiScalarMul {
                        points,
                        scalars,
                        predicate,
                        outputs,
                    } => {
                        let arity = points.len() + scalars.len() + 1;
                        self.msm_arities.insert(arity);
                        let args: Vec<String> = points
                            .iter()
                            .chain(scalars.iter())
                            .chain(std::iter::once(predicate))
                            .map(|fi| self.format_input(fi, prefix))
                            .collect();
                        self.wires.insert(format!("{prefix}w{}", outputs.0.0));
                        self.wires.insert(format!("{prefix}w{}", outputs.1.0));
                        defined.insert(outputs.0);
                        defined.insert(outputs.1);
                        self.assertions.push(format!(
                            "(assert (= {prefix}w{} (msm_x_{arity} {})))",
                            outputs.0.0,
                            args.join(" ")
                        ));
                        self.assertions.push(format!(
                            "(assert (= {prefix}w{} (msm_y_{arity} {})))",
                            outputs.1.0,
                            args.join(" ")
                        ));
                    }
                    other => bail!("unsupported BlackBoxFuncCall in smt_checker: {other}"),
                },
                Opcode::BrilligCall { .. } => {}
                other => bail!("unsupported ACIR opcode in smt_checker: {other:?}"),
            }
        }
        Ok(())
    }

    pub fn assert_raw(&mut self, expr: impl Into<String>) {
        self.assertions.push(expr.into());
    }

    pub fn has_wire(&self, name: &str) -> bool {
        self.wires.contains(name)
    }

    pub fn build(self) -> String {
        let mut lines = vec![
            "(set-logic ALL)".to_string(),
            format!("(define-sort F () (_ FiniteField {BN254_FR_PRIME}))"),
        ];
        if self.has_poseidon2 {
            for k in 0..4 {
                lines.push(format!("(declare-fun p2_{k} (F F F F) F)"));
            }
        }
        for arity in &self.msm_arities {
            let sorts = vec!["F"; *arity].join(" ");
            lines.push(format!("(declare-fun msm_x_{arity} ({sorts}) F)"));
            lines.push(format!("(declare-fun msm_y_{arity} ({sorts}) F)"));
        }
        for w in &self.wires {
            lines.push(format!("(declare-const {w} F)"));
        }
        lines.extend(self.assertions);
        lines.push("(check-sat)".to_string());
        lines.join("\n")
    }

    fn format_input(&mut self, fi: &FunctionInput<FieldElement>, prefix: &str) -> String {
        match fi {
            FunctionInput::Constant(c) => ff_literal(*c),
            FunctionInput::Witness(w) => {
                let name = format!("{prefix}w{}", w.0);
                self.wires.insert(name.clone());
                name
            }
        }
    }
}

fn format_mul_term(c: FieldElement, a: Witness, b: Witness, prefix: &str) -> String {
    let prod = format!("(ff.mul {prefix}w{} {prefix}w{})", a.0, b.0);
    if c.is_one() {
        prod
    } else {
        format!("(ff.mul {} {prod})", ff_literal(c))
    }
}

fn format_lin_term(c: FieldElement, w: Witness, prefix: &str) -> String {
    let var = format!("{prefix}w{}", w.0);
    if c.is_one() {
        var
    } else {
        format!("(ff.mul {} {var})", ff_literal(c))
    }
}

fn combine_ff_add(terms: &[String]) -> String {
    if terms.len() == 1 {
        terms[0].clone()
    } else {
        format!("(ff.add {})", terms.join(" "))
    }
}

