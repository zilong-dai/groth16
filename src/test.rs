use crate::{prepare_verifying_key, Groth16, serialize::ProofWithPublicInputs};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng, UniformRand,
};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a *= &b;
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

fn test_prove_and_verify<E>(n_iters: usize)
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    for _ in 0..n_iters {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());
        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof).unwrap());
    }
}

fn test_rerandomize<E>()
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    for _ in 0..10 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof1 = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        // Rerandomize the proof, then rerandomize that
        let proof2 = Groth16::<E>::rerandomize_proof(&vk, &proof1, &mut rng);
        let proof3 = Groth16::<E>::rerandomize_proof(&vk, &proof2, &mut rng);

        // Check correctness: a rerandomized proof validates when the original validates
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof1).unwrap());
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof2).unwrap());
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof3).unwrap());

        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof1).unwrap());
        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof2).unwrap());
        assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &[a], &proof3).unwrap());

        // Check that the proofs are not equal as group elements
        assert!(proof1 != proof2);
        assert!(proof1 != proof3);
        assert!(proof2 != proof3);
    }
}

mod bls12_377 {
    use super::{test_prove_and_verify, test_rerandomize};
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_377>(100);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<Bls12_377>();
    }
}

mod bw6_761 {
    use super::{test_prove_and_verify, test_rerandomize};

    use ark_bw6_761::BW6_761;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<BW6_761>(1);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<BW6_761>();
    }
}

mod serialize {
    use super::{prepare_verifying_key, ProofWithPublicInputs};
    use crate::{ProvingKey, VerifyingKey};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    use super::{CircuitSpecificSetupSNARK, Groth16, MySillyCircuit};
    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn test_key_consistence() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
        let (pk2, vk2) =
            Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();

        assert_ne!(pk, pk2, "the twice pk is equal");
        assert_ne!(vk, vk2, "the twice vk is equal");
    }

    #[test]
    fn test_key_serialize() {
        // reference: https://docs.rs/ark-serialize/latest/ark_serialize/

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pk, _vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();

        let mut pk_uncompressed_bytes = Vec::<u8>::new();
        pk.serialize_uncompressed(&mut pk_uncompressed_bytes)
            .expect("pk serialize uncompress failed");

        let pk2 = ProvingKey::<E>::deserialize_uncompressed(&*pk_uncompressed_bytes)
            .expect("pk deserialize uncompress failed");

        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_verify_serialize() {
        let proof_json_str = "{\"CommitmentPok\":\"400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"Commitments\":\"\",\"pi_a\":[\"0f2c7e7558ac384e5144da6163aac2442e4fb7f37169f0757b9ae2771cb243eed2d5f0887649f1b04f0d16eb8697e167\",\"0d6220caaf80aa15208ee3a14cad4b4121eeb0e1a38a695f15ca411a534fb8a5bdb625c329a9c947c6b619b18955e77b\"],\"pi_b\":[[\"17bcbcc3154b6387facb5d7be7cb7b5b80c7cc5ec91c276d5cfc9172472ae32a1a705efb20f7792203501cddcc45ea53\",\"121fade8a42569ca463d5e430b097cfcb322b6bca49e65a9a79042783ca35a98497dafd9334d3f90d044e87427eb22b8\"],[\"156ba2ecd572566b890c33b03770f4d6579659552cbfb175949b160d7d8f7955282d3c88d69ca9a575df402a014f2b1f\",\"11ae446bdf06d7ef091bf7dab3910bb1639a1488451c6637ad1c34b27c8990c28e064c9060fc11e0b61591cf575b8eaa\"]],\"pi_c\":[\"19cfcf48750cbaace42bcf4dbac41bddb1bd10c8b2949ad6f148e816e4e005c38e63ca7da76d21d8c5d6096976f22d8f\",\"148f31c6d8f1d38fa41b8a3317217421857f6579e994a58265d1e6acc8b4cd6b055ebe5e3fbef17c249697304de5383b\"],\"public_inputs\":[\"00000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"00000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}";
        let vk_json_str = "{\"CommitmentKey\":\"120e442ed262bdef19aa733dc370f4f9b6b9679e11134f8a9e5a49d4bf448e39719e3bae3d0afd8bfd5f0a3dd4d6363708b7ddda678ae501f1f3fb7182218721fd5c3a303652cbb1c9a5fa7f97637f83cffdf15322621a4ece8d0e76c86607010016d043f12649a8f61318314eb25799321cfba0a5a432cdbe9cea6da79e7cd98c3425fbe5abe79c70ab42d0bdbd70c01362a3cb8ceca3b05d551c63ee0f68b8d4654248c3e4c1669404e65fbca9b5991f895612530ee922a1356af1aac153840e54fd46478c0ea487a914394449269ebcb1ab852e6f773ce63017737703376e7428eb363d80b3f5d204775c0a3676241612a773127468f033422687871d88f191cbb0f01f72779da2dceb9873793d3af278f0376995b48f3f76493cd0db45a80b652a80114300448a86bbf9e87618fdf935dd49a6270e820d346b1970a1fcd96b5ef723438118a0cef5d049eb619233067886a4479e96f2ab8521dc86b1ab1cdf7d9f6545115b101e6bce52732690c27d0685ef9bdf59c139530ab1cb54224e\",\"PublicAndCommitmentCommitted\":[],\"alpha_g1\":[\"028124740d6d1c787f1e0ca2af218523339acd9d608828f324c53779bd6690e0ded218905375df49134af8bce2dd9039\",\"03c221d18ae071b4a9d6c81e80cf1e678768fb9c3bc15dc3d6aa1a5274c84f0799697ff4e878c49b08b94f3d5b4c71d4\"],\"beta_g2\":[[\"11e51a77242f8c9967b693839ff08ba9bf401985b11174428bcec1ff7095b03ee2ffda3375f25df94cb99e0cbaf37617\",\"07d8532dcfd93087765de07c745a5b3b8f44d87696b4be892214d01cb42d3788e34e50f59d622c564e02ba20b5a2b1ff\"],[\"109c6fd1a49b26ff19ddb47479a7bdc2529262e0a5ff8f049b5c027d744e18cec1ebb1d1ba11526509b4c3ce3d3ae5a9\",\"059ec868978203fa3523e20c4c2c40b4167449c3182b3ff83d2e9e94e7fbe792050dfd5bef0351f453c495ab821d62a4\"]],\"delta_g2\":[[\"0e30f8147364e09f358147c7c7618fc5c1f425a50c394c02796b885b962a5cfd1075b31e52777077898219f8a5632ca3\",\"061d9f9424ded1fc4289d3d630505ac9343c55748b284fa44946b9216f5e6e445efdf036ec93473e67e847a39d9aa4ce\"],[\"0b411e3f4c8a4869acac167110ff4c55b05af736551a780f14a2834069f347e22cf990e5d48dfca6ee230b0f2eada7ed\",\"06218f3ebde312b7fd6e32ea8ebda22cba02b7e3173bb76cd1e40aa0c27e1f3edb79069930c532d9a774ecf656d1509c\"]],\"gamma_abc_g1\":[[\"01f9d624c8530a0d771d4cc9d101c926371500c57b57365f1959be4f56bb21393abe63805bdd1462e03e6ca8464d8879\",\"174a45e6699acced574b0c2a632e23d53fc9c06379f4f284ac469c461ed9a3122e41da993545308f67288d55c157c25c\"],[\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], [\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"]],\"gamma_g2\":[[\"150934ad1bb6de077fc197dad5760abe1f46164cc6c00fbd555c7ba91c843f395d7d7c252a24f6dc35c3f8c7dc4a4a75\",\"0e4a5d6361c993850bf80f6dc93d657cda9eeac9cf0d8fc18749a4ee1644713e1b03181cb4ddc0dc5707ec52f74f7a0b\"],[\"0c2b2d9642d838d7c4d862eb66f7815bed1b730dce85fffcad6870d43cd1a68ed049cec36d6ddc7ff36c4aa3997d6918\",\"0c99873e1fd5a07a2aa519115fa0282c0284db746e351ec0dcceea98bfc8bde7059f7db3274964f14c6eb9abbacdc8b9\"]]}";

        let proof_with_publicinputs = ProofWithPublicInputs::<E>::from_json(proof_json_str);
        let proof_json = proof_with_publicinputs.to_json();
        let proof_with_publicinputs2 = ProofWithPublicInputs::<E>::from_json(&proof_json);

        let vk = VerifyingKey::<E>::from_json(&vk_json_str);
        let vk_json = vk.to_json();
        let vk2 = VerifyingKey::<E>::from_json(&vk_json);

        let pvk = prepare_verifying_key(&vk2);

        assert_eq!(
            Groth16::<E>::verify_proof(&pvk, &proof_with_publicinputs2.proof, &proof_with_publicinputs2.public_inputs), Ok(true)
        );
    }
}
