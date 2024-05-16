use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_ff::{BigInt, Field, PrimeField};
use ark_serialize::*;
use ark_std::{ops::AddAssign, vec::Vec};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::hash::{expand_msg_xmd, DST};

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// The `A` element in `G1`.
    pub a: E::G1Affine,
    /// The `B` element in `G2`.
    pub b: E::G2Affine,
    /// The `C` element in `G1`.
    pub c: E::G1Affine,
}

impl<E: Pairing> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProofWithPublicInputs<E: Pairing> {
    proof: Proof<E>,
    public_inputs: Vec<E::ScalarField>,
    pub extra: G1Affine,
}

impl ProofWithPublicInputs<Bls12_381> {
    pub fn new() -> Self {
        let proof = Proof::default();
        let public_inputs = vec![];
        let extra = G1Affine::default();
        Self {
            proof,
            public_inputs,
            extra,
        }
    }

    pub fn proof(&self) -> &Proof<Bls12_381> {
        &self.proof
    }

    pub fn public_inputs(&self) -> &Vec<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField> {
        &self.public_inputs
    }

    pub fn fromjson(json: &str) -> Self {
        #[derive(Deserialize, Serialize)]
        struct ProofMap {
            /// The `A` element in `G1`.
            pub pi_a: [String; 2],
            /// The `B` element in `G2`.
            pub pi_b: [[String; 2]; 2],
            /// The `C` element in `G1`.
            pub pi_c: [String; 2],
            pub public_inputs: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub PublicAndCommitmentCommitted: Option<Vec<Vec<u64>>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub Commitments: Option<String>,
        }

        fn hexstr_2_fq(s: &str) -> Fq {
            let bytes = hex::decode(s).expect("hex decoding failed");
            let repr =
                BigInt::try_from(BigUint::from_bytes_be(&bytes)).expect("Bigint conversion failed");
            Fq::from_bigint(repr).expect("from bigint failed")
        }

        fn hexstr_2_fr(s: &str) -> Fr {
            let bytes = hex::decode(s).expect("hex decoding failed");
            let repr =
                BigInt::try_from(BigUint::from_bytes_be(&bytes)).expect("Bigint conversion failed");
            Fr::from_bigint(repr).expect("from bigint failed")
            // Fr::from_le_bytes_mod_order(&bytes)
        }

        let proof_map: ProofMap = serde_json::from_str(json).expect("JSON was not well-formatted");

        let num_u64s = if Fq::MODULUS_BIT_SIZE % 64 == 0 {
            Fq::MODULUS_BIT_SIZE / 64
        } else {
            Fq::MODULUS_BIT_SIZE / 64 + 1
        } as usize;

        let pi_a = G1Affine::new(
            hexstr_2_fq(&proof_map.pi_a[0]),
            hexstr_2_fq(&proof_map.pi_a[1]),
        );

        let pi_b = G2Affine::new(
            Fq2::new(
                hexstr_2_fq(&proof_map.pi_b[0][0]),
                hexstr_2_fq(&proof_map.pi_b[0][1]),
            ),
            Fq2::new(
                hexstr_2_fq(&proof_map.pi_b[1][0]),
                hexstr_2_fq(&proof_map.pi_b[1][1]),
            ),
        );
        let pi_c = G1Affine::new(
            hexstr_2_fq(&proof_map.pi_c[0]),
            hexstr_2_fq(&proof_map.pi_c[1]),
        );
        let mut public_inputs: Vec<Fr> = proof_map
            .public_inputs
            .iter()
            .map(|s: &String| hexstr_2_fr(s))
            .collect();

        let commitments_serialized = proof_map.Commitments.clone().expect("commitments is none");
        let commitment_prehash_serialized = hex::decode(&commitments_serialized[0..num_u64s * 32])
            .expect("decode commitments failed"); // msg

        let bytes_len = 32;
        let l = 16 + bytes_len;
        let res_bytes = expand_msg_xmd(&commitment_prehash_serialized, DST, l);

        let com_public = Fr::from_be_bytes_mod_order(&res_bytes);
        public_inputs.push(com_public);

        let mut comm_sum = G1Projective::default();
        if let Some(commitment) = proof_map.Commitments {
            let comm_bytes = hex::decode(commitment).expect("decode commitments failed");
            let comm_points: Vec<G1Affine> = comm_bytes
                .chunks(num_u64s * 16)
                .map(|chunk| {
                    let reprx = BigInt::try_from(BigUint::from_bytes_be(&chunk[..num_u64s*8]))
                        .expect("Bigint conversion failed");
                    let repry = BigInt::try_from(BigUint::from_bytes_be(&chunk[num_u64s*8..]))
                        .expect("Bigint conversion failed");
                    G1Affine::new(
                        Fq::from_bigint(reprx).expect("from bigint failed"),
                        Fq::from_bigint(repry).expect("from bigint failed"),
                    )
                })
                .collect();
            for comm_point in comm_points.iter() {
                comm_sum.add_assign(comm_point);
            }
            public_inputs.push(Fr::ONE)
        }

        let extra: G1Affine = comm_sum.try_into().unwrap();

        Self {
            proof: Proof {
                a: pi_a,
                b: pi_b,
                c: pi_c,
            },
            public_inputs,
            extra,
        }
    }

    pub fn tojson(&self) -> String {
        todo!()
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: E::G1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: E::G2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: E::G2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: E::G2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

impl VerifyingKey<Bls12_381> {
    fn new() -> Self {
        Self::default()
    }

    pub fn fromjson(json: &str) -> Self {
        #[derive(Deserialize, Serialize)]
        struct VerifyingKeyMap {
            /// The `alpha * G`, where `G` is the generator of `E::G1`.
            pub alpha_g1: [String; 2],
            /// The `alpha * H`, where `H` is the generator of `E::G2`.
            pub beta_g2: [[String; 2]; 2],
            /// The `gamma * H`, where `H` is the generator of `E::G2`.
            pub gamma_g2: [[String; 2]; 2],
            /// The `delta * H`, where `H` is the generator of `E::G2`.
            pub delta_g2: [[String; 2]; 2],
            /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where
            /// `H` is the generator of `E::G1`.
            pub gamma_abc_g1: Vec<Vec<String>>,
        }

        fn hexstr_2_fq(s: &str) -> Fq {
            let bytes = hex::decode(s).expect("hex decoding failed");
            let repr =
                BigInt::try_from(BigUint::from_bytes_be(&bytes)).expect("Bigint conversion failed");
            Fq::from_bigint(repr).expect("from bigint failed")
        }

        fn hexstr_2_fr(s: &str) -> Fr {
            let bytes = hex::decode(s).expect("hex decoding failed");
            let repr =
                BigInt::try_from(BigUint::from_bytes_be(&bytes)).expect("Bigint conversion failed");
            Fr::from_bigint(repr).expect("from bigint failed")
            // Fr::from_le_bytes_mod_order(&bytes)
        }

        let vk_map: VerifyingKeyMap =
            serde_json::from_str(json).expect("JSON was not well-formatted");

        let alpha_g1 = G1Affine::new(
            hexstr_2_fq(&vk_map.alpha_g1[0]),
            hexstr_2_fq(&vk_map.alpha_g1[1]),
        );

        let beta_g2 = G2Affine::new(
            Fq2::new(
                hexstr_2_fq(&vk_map.beta_g2[0][0]),
                hexstr_2_fq(&vk_map.beta_g2[0][1]),
            ),
            Fq2::new(
                hexstr_2_fq(&vk_map.beta_g2[1][0]),
                hexstr_2_fq(&vk_map.beta_g2[1][1]),
            ),
        );

        let gamma_g2 = G2Affine::new(
            Fq2::new(
                hexstr_2_fq(&vk_map.gamma_g2[0][0]),
                hexstr_2_fq(&vk_map.gamma_g2[0][1]),
            ),
            Fq2::new(
                hexstr_2_fq(&vk_map.gamma_g2[1][0]),
                hexstr_2_fq(&vk_map.gamma_g2[1][1]),
            ),
        );

        let delta_g2 = G2Affine::new(
            Fq2::new(
                hexstr_2_fq(&vk_map.delta_g2[0][0]),
                hexstr_2_fq(&vk_map.delta_g2[0][1]),
            ),
            Fq2::new(
                hexstr_2_fq(&vk_map.delta_g2[1][0]),
                hexstr_2_fq(&vk_map.delta_g2[1][1]),
            ),
        );

        let gamma_abc_g1 = vk_map
            .gamma_abc_g1
            .iter()
            .map(|s| G1Affine::new(hexstr_2_fq(&s[0]), hexstr_2_fq(&s[1])))
            .collect();

        Self {
            alpha_g1,
            beta_g2,

            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        }
    }

    pub fn tojson(&self) -> String {
        todo!()
    }
}

impl<E> Absorb for VerifyingKey<E>
where
    E: Pairing,
    E::G1Affine: Absorb,
    E::G2Affine: Absorb,
{
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.alpha_g1.to_sponge_bytes(dest);
        self.beta_g2.to_sponge_bytes(dest);
        self.gamma_g2.to_sponge_bytes(dest);
        self.delta_g2.to_sponge_bytes(dest);
        self.gamma_abc_g1
            .iter()
            .for_each(|g| g.to_sponge_bytes(dest));
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.alpha_g1.to_sponge_field_elements(dest);
        self.beta_g2.to_sponge_field_elements(dest);
        self.gamma_g2.to_sponge_field_elements(dest);
        self.delta_g2.to_sponge_field_elements(dest);
        self.gamma_abc_g1
            .iter()
            .for_each(|g| g.to_sponge_field_elements(dest));
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: E::TargetField,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: E::G2Prepared,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: E::G2Prepared,
}

impl<E: Pairing> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: Pairing> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        crate::prepare_verifying_key(&other)
    }
}

impl<E: Pairing> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: E::TargetField::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: E::G1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<E::G1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<E::G1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<E::G2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<E::G1Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<E::G1Affine>,
}
