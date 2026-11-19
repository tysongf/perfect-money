use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{Circuit, Opcode};
use acir::native_types::{Expression, Witness, WitnessMap};
use acir::{AcirField, FieldElement};
use acvm_blackbox_solver::BlackBoxFunctionSolver;
use bn254_blackbox_solver::Bn254BlackBoxSolver;

/// Detailed failure produced when a witness violates an ACIR constraint.
#[derive(Debug, Clone)]
pub struct ConstraintFailure {
    pub opcode_index: usize,
    pub reason: String,
}

/// Evaluates all constraint opcodes in `circuit` against `witness` (skipping Brillig hints).
pub fn verify_constraints(
    circuit: &Circuit<FieldElement>,
    witness: &WitnessMap<FieldElement>,
    solver: &Bn254BlackBoxSolver,
) -> Result<(), ConstraintFailure> {
    for (idx, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expr) => {
                let val = eval_expression(expr, witness).map_err(|reason| ConstraintFailure {
                    opcode_index: idx,
                    reason,
                })?;
                if !val.is_zero() {
                    return Err(ConstraintFailure {
                        opcode_index: idx,
                        reason: format!("AssertZero evaluated to {val} != 0"),
                    });
                }
            }
            Opcode::BlackBoxFuncCall(call) => {
                eval_blackbox(call, witness, solver).map_err(|reason| ConstraintFailure {
                    opcode_index: idx,
                    reason,
                })?;
            }
            // Deliberately ignore Brillig hints: unconstrained code must never act as constraints.
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryInit { .. } | Opcode::MemoryOp { .. } | Opcode::Call { .. } => {
                return Err(ConstraintFailure {
                    opcode_index: idx,
                    reason: format!("Unsupported ACIR opcode encountered: {opcode:?}"),
                });
            }
        }
    }
    Ok(())
}

fn eval_expression(
    expr: &Expression<FieldElement>,
    witness: &WitnessMap<FieldElement>,
) -> Result<FieldElement, String> {
    let mut sum = expr.q_c;
    for &(coeff, wl, wr) in &expr.mul_terms {
        let vl = read_witness(witness, wl)?;
        let vr = read_witness(witness, wr)?;
        sum += coeff * vl * vr;
    }
    for &(coeff, w) in &expr.linear_combinations {
        let v = read_witness(witness, w)?;
        sum += coeff * v;
    }
    Ok(sum)
}

fn eval_blackbox(
    call: &BlackBoxFuncCall<FieldElement>,
    witness: &WitnessMap<FieldElement>,
    solver: &Bn254BlackBoxSolver,
) -> Result<(), String> {
    match call {
        BlackBoxFuncCall::RANGE { input, num_bits } => {
            let v = eval_input(witness, *input)?;
            if v.num_bits() > *num_bits {
                return Err(format!(
                    "RANGE({num_bits}) failed: value requires {} bits",
                    v.num_bits()
                ));
            }
            Ok(())
        }
        BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
            let in_vals = inputs
                .iter()
                .map(|i| eval_input(witness, *i))
                .collect::<Result<Vec<_>, _>>()?;
            let expected = solver
                .poseidon2_permutation(&in_vals)
                .map_err(|e| format!("Poseidon2Permutation failed: {e}"))?;
            if expected.len() != outputs.len() {
                return Err("Poseidon2 output length mismatch".to_string());
            }
            for (out_w, exp_v) in outputs.iter().zip(expected.iter()) {
                let actual = read_witness(witness, *out_w)?;
                if actual != *exp_v {
                    return Err(format!(
                        "Poseidon2 output {out_w} mismatch: got {actual}, expected {exp_v}"
                    ));
                }
            }
            Ok(())
        }
        BlackBoxFuncCall::MultiScalarMul {
            points,
            scalars,
            predicate,
            outputs,
        } => {
            let pred_val = eval_input(witness, *predicate)?;
            if !pred_val.is_zero() && !pred_val.is_one() {
                return Err(format!("MultiScalarMul predicate must be 0 or 1, got {pred_val}"));
            }
            let pt_vals = points
                .iter()
                .map(|i| eval_input(witness, *i))
                .collect::<Result<Vec<_>, _>>()?;
            let sc_vals = scalars
                .iter()
                .map(|i| eval_input(witness, *i))
                .collect::<Result<Vec<_>, _>>()?;

            let mut lo = Vec::with_capacity(sc_vals.len() / 2);
            let mut hi = Vec::with_capacity(sc_vals.len() / 2);
            for (i, s) in sc_vals.into_iter().enumerate() {
                if i % 2 == 0 {
                    lo.push(s);
                } else {
                    hi.push(s);
                }
            }

            let (exp_x, exp_y) = solver
                .multi_scalar_mul(&pt_vals, &lo, &hi, pred_val.is_one())
                .map_err(|e| format!("MultiScalarMul solver error: {e}"))?;
            let act_x = read_witness(witness, outputs.0)?;
            let act_y = read_witness(witness, outputs.1)?;
            if act_x != exp_x || act_y != exp_y {
                return Err("MultiScalarMul output mismatch".to_string());
            }
            Ok(())
        }
        BlackBoxFuncCall::EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs,
        } => {
            let pred_val = eval_input(witness, *predicate)?;
            if !pred_val.is_zero() && !pred_val.is_one() {
                return Err(format!(
                    "EmbeddedCurveAdd predicate must be 0 or 1, got {pred_val}"
                ));
            }
            let x1 = eval_input(witness, input1[0])?;
            let y1 = eval_input(witness, input1[1])?;
            let x2 = eval_input(witness, input2[0])?;
            let y2 = eval_input(witness, input2[1])?;
            let (exp_x, exp_y) = solver
                .ec_add(&x1, &y1, &x2, &y2, pred_val.is_one())
                .map_err(|e| format!("EmbeddedCurveAdd solver error: {e}"))?;
            let act_x = read_witness(witness, outputs.0)?;
            let act_y = read_witness(witness, outputs.1)?;
            if act_x != exp_x || act_y != exp_y {
                return Err("EmbeddedCurveAdd output mismatch".to_string());
            }
            Ok(())
        }
        other => Err(format!("Unsupported BlackBoxFuncCall: {other}")),
    }
}

fn eval_input(
    witness: &WitnessMap<FieldElement>,
    input: FunctionInput<FieldElement>,
) -> Result<FieldElement, String> {
    match input {
        FunctionInput::Constant(c) => Ok(c),
        FunctionInput::Witness(w) => read_witness(witness, w),
    }
}

fn read_witness(witness: &WitnessMap<FieldElement>, w: Witness) -> Result<FieldElement, String> {
    witness
        .get(&w)
        .copied()
        .ok_or_else(|| format!("missing witness {w}"))
}

