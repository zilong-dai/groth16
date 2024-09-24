use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_std::rand::{Rng, RngCore, SeedableRng};

use ark_bls12_381::{Bls12_381, Fr};
use ark_bn254::Fq;
use ark_ff::PrimeField;
use ark_std::test_rng;

use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};

use ark_groth16::gadgets::AllocatedEmulatedFpVar as AllocatedEmVar;
#[derive(Debug, Clone)]
struct MulDemo2<F: PrimeField> {
    a: Option<F>,
    b: Option<F>,
    c: Option<F>,
}

impl<TargetF: PrimeField, BaseF: PrimeField> ConstraintSynthesizer<BaseF> for MulDemo2<TargetF> {
    fn generate_constraints(self, cs: ConstraintSystemRef<BaseF>) -> Result<(), SynthesisError> {
        let a = AllocatedEmVar::new_witness(cs.clone(), || Ok(self.a.unwrap())).unwrap();
        let b = AllocatedEmVar::new_witness(cs.clone(), || Ok(self.b.unwrap())).unwrap();
        let c = AllocatedEmVar::new_input(cs.clone(), || Ok(self.c.unwrap())).unwrap();

        let amulb = a.mul(&b);

        c.base_value
            .enforce_equal(&amulb.clone().unwrap().base_value)
            .unwrap();
        if !cs.is_in_setup_mode() {
            println!("c: {:?}", c.value());
            println!("amulb: {:?}", amulb.clone().unwrap().value());
        }

        Ok(())
    }
}

#[test]
fn test_emulated_fpvar_groth16_2() {
    use ark_groth16::Groth16;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let a: Fq = rng.gen();
    let b: Fq = rng.gen();
    let c = a * b;

    let circuit = MulDemo2::<Fq> {
        a: Some(a),
        b: Some(b),
        c: Some(c),
    };

    let (pk, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut rng).unwrap();

    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();


    let cc = c.into_bigint();
    let cc = Fr::from_bigint(cc).unwrap();

    let public_input = vec![cc];

    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_input[..], &proof).unwrap());
}
