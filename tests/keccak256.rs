#[cfg(feature = "r1cs")]
mod tests {
    use ark_groth16::gadgets::{keccak256_bytes as keccak_bytes_gadget, Keccak256Gadget};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };
    use bitvec::{order::Lsb0, vec::BitVec};

    use ark_ff::PrimeField;
    use ark_groth16::gadgets::keccak256 as keccak_gadget;
    use ark_r1cs_std::{boolean::Boolean, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystemRef;
    use tiny_keccak::{Hasher, Keccak};

    use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};

    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};

    #[derive(Debug, Clone)]
    struct KeccakDemo {
        preimage: Vec<u8>,
        output: Vec<u8>,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for KeccakDemo {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let preimage: Vec<UInt8<F>> = self
                .preimage
                .iter()
                .map(|b| UInt8::<F>::new_witness(cs.clone(), || Ok(b)).unwrap())
                .collect();
            let output: Vec<UInt8<F>> = self
                .output
                .iter()
                .map(|b| UInt8::<F>::new_input(cs.clone(), || Ok(b)).unwrap())
                .collect();

            let hash = Keccak256Gadget::digest(&preimage);

            for (out_byte, hash_bytes) in output.iter().zip(hash.iter()) {
                out_byte.enforce_equal(hash_bytes)?;
            }

            Ok(())
        }
    }

    fn keccak256(preimage: &[u8]) -> [u8; 32] {
        let mut keccak = Keccak::v256();

        keccak.update(preimage);

        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);
        hash
    }

    fn bytes_to_bitvec<F: PrimeField>(bytes: &[u8]) -> Vec<Boolean<F>> {
        let bits = BitVec::<Lsb0, u8>::from_slice(&bytes);
        bits.iter().map(|b| Boolean::constant(*b)).collect()
    }

    fn bits_to_bytevec<F: PrimeField>(bits: &[Boolean<F>]) -> Vec<u8> {
        let result: Vec<bool> = bits.iter().map(|b| b.value().unwrap()).collect();
        let mut bv = BitVec::<Lsb0, u8>::new();
        for bit in result {
            bv.push(bit);
        }
        bv.as_slice().iter().map(|b| *b).collect()
    }

    #[test]
    fn test_keccak256() {
        use ark_bls12_381::Fr;

        let preimage = hex::decode("bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46").unwrap();
        let expected = keccak256(&preimage);

        let preimage = bytes_to_bitvec::<Fr>(&preimage);

        let result = keccak_gadget(&preimage).unwrap();

        let result = bits_to_bytevec(&result);

        assert_eq!(hex::encode(&result), hex::encode(&expected));
    }

    #[test]
    fn test_keccak256_bytes() {
        use ark_bls12_381::Fr;
        use ark_r1cs_std::uint8::UInt8;

        let preimage = hex::decode("bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46").unwrap();
        let expected = keccak256(&preimage);

        let preimage = preimage
            .iter()
            .map(|b| UInt8::<Fr>::constant(*b))
            .collect::<Vec<_>>();

        let result = keccak_bytes_gadget(&preimage);
        let result = result
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(hex::encode(&result), hex::encode(&expected));
    }

    #[test]
    fn test_keccak256_gadget() {
        use ark_bls12_381::Fr;
        use ark_r1cs_std::uint8::UInt8;

        let preimage = hex::decode("bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46").unwrap();
        let expected = keccak256(&preimage);

        let preimage = preimage
            .iter()
            .map(|b| UInt8::<Fr>::constant(*b))
            .collect::<Vec<_>>();

        // let result = Keccak256Gadget::digest(&preimage);
        let mut keccak_gadget_var = Keccak256Gadget::new();
        keccak_gadget_var.update(&preimage[0..1]);
        keccak_gadget_var.update(&preimage[1..2]);
        keccak_gadget_var.update(&preimage[2..]);

        let result = keccak_gadget_var.finalize();

        let result = result
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(hex::encode(&result), hex::encode(&expected));
    }

    #[test]
    fn test_keccak256_prove() {
        use ark_bls12_381::{Bls12_381, Fr};
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_groth16::Groth16;

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let preimage = hex::decode("bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f46").unwrap();
        let expected = keccak256(&preimage);

        let circuit = KeccakDemo {
            preimage: preimage.clone(),
            output: expected.to_vec(),
        };

        let (pk, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut rng).unwrap();

        let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();

        let public_input: Vec<Fr> = expected
            .iter()
            .flat_map(|b| {
                (0..8)
                    .into_iter()
                    .map(|i| Fr::from(b >> i & 1))
                    .collect::<Vec<_>>()
            })
            .collect();

        let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        assert!(
            Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_input, &proof).unwrap()
        );
    }
}
