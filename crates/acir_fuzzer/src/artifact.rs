use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use acir::FieldElement;
use acir::circuit::Program;
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;

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

/// Loaded Noir ACIR artifact together with decoded bytecode and ABI witness map.
pub struct LoadedArtifact {
    pub program: Program<FieldElement>,
    pub abi_witnesses: Vec<Witness>,
    pub label_to_witness: BTreeMap<String, Witness>,
    pub witness_to_label: BTreeMap<Witness, String>,
}

/// Loads a compiled Noir `.json` artifact and validates ABI witness mapping.
pub fn load_artifact(path: &Path) -> Result<LoadedArtifact> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read artifact JSON at {}", path.display()))?;
    let parsed: NargoArtifactJson =
        serde_json::from_str(&raw).context("failed to parse Noir artifact JSON")?;

    let bytecode_bytes = base64::engine::general_purpose::STANDARD
        .decode(parsed.bytecode.trim())
        .context("failed to base64-decode ACIR bytecode")?;
    let program = Program::<FieldElement>::deserialize_program(&bytecode_bytes)
        .context("failed to deserialize ACIR program")?;

    let main_circuit = program
        .functions
        .first()
        .context("ACIR program contains no functions")?;

    let mut pub_names = Vec::new();
    let mut priv_names = Vec::new();
    for param in &parsed.abi.parameters {
        let target = if param.visibility == "public" {
            &mut pub_names
        } else {
            &mut priv_names
        };
        flatten_abi_type(&param.name, &param.param_type, target);
    }

    let pub_witnesses: Vec<Witness> = main_circuit.public_parameters.0.iter().copied().collect();
    let priv_witnesses: Vec<Witness> = main_circuit.private_parameters.iter().copied().collect();

    if pub_names.len() != pub_witnesses.len() {
        bail!(
            "ABI public parameter count ({}) does not match ACIR public_parameters ({})",
            pub_names.len(),
            pub_witnesses.len()
        );
    }
    if priv_names.len() != priv_witnesses.len() {
        bail!(
            "ABI private parameter count ({}) does not match ACIR private_parameters ({})",
            priv_names.len(),
            priv_witnesses.len()
        );
    }

    let mut abi_witnesses = Vec::with_capacity(pub_names.len() + priv_names.len());
    let mut label_to_witness = BTreeMap::new();
    let mut witness_to_label = BTreeMap::new();

    for (path_name, witness) in pub_names
        .into_iter()
        .zip(pub_witnesses)
        .chain(priv_names.into_iter().zip(priv_witnesses))
    {
        label_to_witness.insert(path_name.clone(), witness);
        witness_to_label.insert(witness, path_name);
        abi_witnesses.push(witness);
    }

    Ok(LoadedArtifact {
        program,
        abi_witnesses,
        label_to_witness,
        witness_to_label,
    })
}

fn flatten_abi_type(prefix: &str, ty: &AbiType, out: &mut Vec<String>) {
    match ty {
        AbiType::Field | AbiType::Boolean | AbiType::Integer { .. } => {
            out.push(prefix.to_string());
        }
        AbiType::Array { length, elem_type } => {
            for idx in 0..*length {
                flatten_abi_type(&format!("{prefix}[{idx}]"), elem_type, out);
            }
        }
        AbiType::Struct { fields, .. } => {
            for f in fields {
                flatten_abi_type(&format!("{prefix}.{}", f.name), &f.field_type, out);
            }
        }
        AbiType::Tuple { fields } => {
            for (idx, f) in fields.iter().enumerate() {
                flatten_abi_type(&format!("{prefix}.{idx}"), f, out);
            }
        }
    }
}

/// Loads the primary `WitnessMap` from a Noir `.gz` witness stack file.
pub fn load_witness_map(path: &Path) -> Result<WitnessMap<FieldElement>> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read witness at {}", path.display()))?;
    let mut stack = WitnessStack::<FieldElement>::deserialize(bytes.as_slice())
        .context("failed to deserialize WitnessStack")?;
    let item = stack
        .pop()
        .context("WitnessStack contains no witness entries")?;
    Ok(item.witness)
}

/// Serializes a `WitnessMap` as a single-item `WitnessStack` `.gz` file for Barretenberg.
pub fn write_witness_map(witness: &WitnessMap<FieldElement>, path: &Path) -> Result<()> {
    let mut stack = WitnessStack::<FieldElement>::default();
    stack.push(0, witness.clone());
    let bytes = stack
        .serialize()
        .context("failed to serialize WitnessStack")?;
    fs::write(path, bytes)
        .with_context(|| format!("failed to write witness to {}", path.display()))?;
    Ok(())
}

