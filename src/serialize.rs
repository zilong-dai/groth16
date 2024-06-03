use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, PrimeField};
use ark_std::vec::Vec;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use ark_ff::BigInteger;

use crate::{Proof, VerifyingKey};

#[derive(Deserialize, Serialize)]
struct G1s {
    #[serde(rename = "x")]
    pub x: String,
    #[serde(rename = "y")]
    pub y: String,
}

#[derive(Deserialize, Serialize)]
struct E2s {
    #[serde(rename = "a0")]
    pub a0: String,
    #[serde(rename = "a1")]
    pub a1: String,
}

#[derive(Deserialize, Serialize)]
struct G2s {
    #[serde(rename = "x")]
    pub x: E2s,
    #[serde(rename = "y")]
    pub y: E2s,
}

#[derive(Deserialize, Serialize)]
struct ProofMap {
    pub pi_a: G1s,
    pub pi_b: G2s,
    pub pi_c: G1s,
    pub public_inputs: Vec<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "PublicAndCommitmentCommitted"
    )]
    pub public_and_commitment_committed: Option<Vec<Vec<u64>>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "Commitments")]
    pub commitments: Option<String>,
}

/// Proof  and PublilcInputs in the Groth16 SNARK.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofWithPublicInputs<E: Pairing> {
    /// Groth16 Proof.
    pub proof: Proof<E>,
    /// Groth16 PublicInputs.
    pub public_inputs: Vec<E::ScalarField>,
}

impl ProofWithPublicInputs<Bls12_381> {
    /// Create a Groth16 ProofWithPublicInputs with default values.
    pub fn new() -> Self {
        let proof = Proof::default();
        let public_inputs = vec![];
        Self {
            proof,
            public_inputs,
        }
    }
    
    /// Create a Groth16 ProofWithPublicInputs from JSON string.
    pub fn from_json(json: &str) -> Self {
        let proof_map: ProofMap = serde_json::from_str(json).expect("JSON was not well-formatted");

        let pi_a = deserialize_g1(&proof_map.pi_a);
        let pi_b = deserialize_g2(&proof_map.pi_b);
        let pi_c = deserialize_g1(&proof_map.pi_c);
        let public_inputs: Vec<Fr> = proof_map
            .public_inputs
            .iter()
            .map(|s: &String| deserialize_fr(s))
            .collect();

        Self {
            proof: Proof {
                a: pi_a,
                b: pi_b,
                c: pi_c,
            },
            public_inputs,
        }
    }

    /// Convert the Groth16 ProofWithPublicInputs to JSON string.
    pub fn to_json(&self) -> String {
        let proof_map = ProofMap {
            pi_a: serialize_g1(&self.proof.a),
            pi_b: serialize_g2(&self.proof.b),
            pi_c: serialize_g1(&self.proof.c),
            public_inputs: self.public_inputs.iter().map(|s| serialize_fr(s)).collect(),
            public_and_commitment_committed: None,
            commitments: None,
        };

        serde_json::to_string(&proof_map).expect("JSON was not well-formatted")
    }
}

#[derive(Deserialize, Serialize)]
struct VerifyingKeyMap {
    alpha_g1: G1s,
    beta_g2: G2s,
    gamma_g2: G2s,
    delta_g2: G2s,
    gamma_abc_g1: Vec<G1s>,
}

impl VerifyingKey<Bls12_381> {
    /// Create a Groth16 VerifyingKey from JSON string.
    pub fn from_json(json: &str) -> Self {
        let vk_map: VerifyingKeyMap =
            serde_json::from_str(json).expect("JSON was not well-formatted");

        let alpha_g1 = deserialize_g1(&vk_map.alpha_g1);
        let beta_g2 = deserialize_g2(&vk_map.beta_g2);
        let gamma_g2 = deserialize_g2(&vk_map.gamma_g2);
        let delta_g2 = deserialize_g2(&vk_map.delta_g2);

        let gamma_abc_g1 = vk_map
            .gamma_abc_g1
            .iter()
            .map(|s| deserialize_g1(&s))
            .collect();

        Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        }
    }

    /// Convert the Groth16 VerifyingKey to JSON string.
    pub fn to_json(&self) -> String {
        let vk_map = VerifyingKeyMap {
            alpha_g1: serialize_g1(&self.alpha_g1),
            beta_g2: serialize_g2(&self.beta_g2),
            gamma_g2: serialize_g2(&self.gamma_g2),
            delta_g2: serialize_g2(&self.delta_g2),
            gamma_abc_g1: self.gamma_abc_g1.iter().map(|s| serialize_g1(&s)).collect(),
        };
        serde_json::to_string(&vk_map).expect("JSON was not well-formatted")
    }
}

fn serialize_g1(g1: &G1Affine) -> G1s {
    G1s {
        x: serialize_fq(&g1.x),
        y: serialize_fq(&g1.y),
    }
}

fn deserialize_g1(g1: &G1s) -> G1Affine {
    if deserialize_fq(&g1.x) == Fq::default() {
        G1Affine::default()
    } else {
        G1Affine::new(deserialize_fq(&g1.x), deserialize_fq(&g1.y))
    }
}

fn serialize_g2(g2: &G2Affine) -> G2s {
    G2s {
        x: E2s {
            a0: serialize_fq(&g2.x.c0),
            a1: serialize_fq(&g2.x.c1),
        },
        y: E2s {
            a0: serialize_fq(&g2.y.c0),
            a1: serialize_fq(&g2.y.c1),
        },
    }
}

fn deserialize_g2(g2s: &G2s) -> G2Affine {
    G2Affine::new(
        Fq2::new(deserialize_fq(&g2s.x.a0), deserialize_fq(&g2s.x.a1)),
        Fq2::new(deserialize_fq(&g2s.y.a0), deserialize_fq(&g2s.y.a1)),
    )
}

fn deserialize_fq(s: &str) -> Fq {
    let bytes = hex::decode(s).expect("hex decoding failed");
    let repr = BigInt::try_from(BigUint::from_bytes_be(&bytes)).expect("Bigint conversion failed");
    Fq::from_bigint(repr).expect("from bigint failed")
}

fn deserialize_fr(s: &str) -> Fr {
    let bytes = hex::decode(s).expect("hex decoding failed");
    let repr = BigInt::try_from(BigUint::from_bytes_be(&bytes)).expect("Bigint conversion failed");
    Fr::from_bigint(repr).expect("from bigint failed")
    // Fr::from_le_bytes_mod_order(&bytes)
}

fn serialize_fq(fq: &Fq) -> String {
    // let fq_bigint = BigUint::try_from(fq.into_bigint()).expect("Bigint conversion failed");
    // format!("{:x}", fq_bigint)
    let fq_bigint = fq.into_bigint().to_bytes_be();
    hex::encode(fq_bigint)
}

fn serialize_fr(fr: &Fr) -> String {
    // let fr_bigint = BigUint::try_from(fr.into_bigint()).expect("Bigint conversion failed");
    // format!("{:x}", fr_bigint)
    let fr_bigint = fr.into_bigint().to_bytes_be();
    hex::encode(fr_bigint)
}
