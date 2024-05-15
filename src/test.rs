use crate::{prepare_verifying_key, Groth16};
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
    use crate::{prepare_verifying_key, ProvingKey};
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
    fn test_proofwithpublicinputs_serialize() {

        let vk_json_str = "{\"CommitmentKey\":\"06096a213949130babeebe3566bcebd085f44ac975e82db17c625df88074942f83abc179867e9c837cfedcc7b26015c015192ac16ca3e5a4453d1f7e9740753852297336ee74bd6c137b084915fe27453781dd226a4946e8ccf3bb98984d3f500d306d63bc8f2b8504a47a0b87e714c229e8d278b571134efc689c601ff87f21c6b1e47a93cc64f09fd0fc2865734bdf17911ec6763122c095926e54f666e1f211d04d2d45185980d5e162879f844144b3a383809d49d43409cfbd364edfb49613f39c4ad92a86e1f2f05e3b34f3a0eb37dc7ab7d6f452708e77d3663ba580b0e32b09b6b14cc65c5a61db237a1444cc16d712a0ad948d191e983253a290e229f3bf3789d5c1cb1d27d356d448e23888d88f93c3a23c0210dfde083ce59ec2011544e4eb4de6c881b96e30bda861510328c0f7365ccf2748ce58fc48bd407bae7d99eed8a0a7d91d254cb207ee372ea90c5c88e0f1b4f1dbf354be76f50bc27fe1280a6926c11728442ebbc798de619a5696d3cfcda72f14af504074bc1b6080\",\"PublicAndCommitmentCommitted\":[[]],\"alpha_g1\":[\"0c95f0f7776d92f77d83e9fd1d8dd6ad7a540cd288ce924fb0b960fa35f457b88cc743c538a979967d4830a0fe5782e8\",\"03fb3932e888b4f7a2b1b668dbd69971e05f0fdb3911b13d30c976850559adb45e0c149e98e144bf3fa621f75ca73d10\"],\"beta_g2\":[[\"036dda265e2aa6923aaa0d6b2b4427b060fb41cc2535bdbead0edc5a368dd1e65c5655c059bfdee7ee7348c593352042\",\"01c6be11024420f42fd65b396c83ea2041ddb362a2ba9cd5d4b5dfa012dd6b0bf5c228fa091b04c30d6fa8016ee9d843\"],[\"18c452c3bb8ba1e345d83e0396f2a57024c6621de08c7d6143ee7146f9808c1508c9367bc32d17a4ed4df7557808a4ee\",\"03619c76fafebda0c7208f921b7f8e6ba5e5def435ed1dad5b84779f8af7cebb16d9a1e0a1963c245d6d59b42a912d80\"]],\"delta_g2\":[[\"0ddf256d896353d46cc427084af2215dacbe047ddbbfc6f245a2a1360560c5300b7c3cfab19082aa348431de62bdc8f6\",\"18bcab0bde6a1079c558059f20cb634cd92278de06f921889772f42f08bbac34f23b45d3eabbfd74f7c9734e3794f595\"],[\"145a9f3a8f38ad63df9fb8b58972fbf7187b75cac053385d50c78c6e102c26e03e2a83043003ffb8c04d1bceb24d287b\",\"0b0321e3a2cbe23e82ab8bf4a1799fa59c83c86fad87f35d1769d3c203e7c63ec24c58b64e4e4faaf330e685ebea963c\"]],\"gamma_abc_g1\":[[\"03ec5d7a5c1b869265b24bc203c77142b0c2cbcb63f9df09041037c0550229f09c8ae5efb4629f349660969892e319a6\",\"1603c916ca70c47694ffc6d084bd710e4e0760fa3c048fda216b0946fcaa5a394d04cb686e20d9259f9a36c9be938787\"],[\"1477fd0c85336a52e638349dfda7fcd19bfdc5a3dd08294d1a31f9d7e246a06ae33f0349d86797fbe7a79d93a2bbac45\",\"02804edf1f724be21398e31fec448523c823f1eccd49507a545475b8d192ae9a05c5faf27f90d28c0642378bab840e5a\"],[\"16c3882d2ed852a36e2c1b1d88aa6c8e551cb81a0922ebe01b23fe30891a2ea489844531c76b9b0b74378d148f491082\",\"0e3f950f0660091cf60feed10f4de9cfac6eddb7c8e3b349a5b9384b3c3f2f25168cb665cb0925dad5725d54c24e6b9c\"],[\"0321c3282c7c3ffba0b3af8edc0ccc72fd850f59080647500da207b85c2f31afc8148d5bf85ce31886fda79bb83102a5\",\"12a9fd8659fd7c9474cd25b53e42734a59619544c26022a02e114ed9c4885762e7c203d7b863dfdeeb401d6590e40af8\"]],\"gamma_g2\":[[\"18482fb8db51ca677d12039abb9536f42182f8b2a713f73fb2129773cd2159a6a001352758659390f392e036d241d809\",\"04ac794d416feb3bb1f3237d4c38e0d1630b8eed048319b1d8f15dee7d01e2f49adb371cbada88dcdda35a1566ef3df8\"],[\"0578b02ff7d068bfc7adb380dbda339f6256b31d54c3d8df3c6493e498705e4a810596654b23d0d961c701a2c247c5fa\",\"0eaabbb2d583e2ac7e8504413b32cda20214312e267d0a5d48b54aa2e33028150560c90151024a4b586a9a9e715f37f7\"]]}";
        let proof_json_str = "{\"CommitmentPok\":\"120d6b661becb51cae8243c73371e1b62cc7b9d911f0479942fba8038e6d4b9446135e766f5d03750c016dea36b4658619744b58453d285dd1e08922ad384116609ad47745ae03a73a0b7177f731403a403b588bc276c0a1a9a5f6aa840e536d\",\"Commitments\":\"0478d616e45b74b4bf45242142d9d6f0b6c7fe9eb3b6ae5ddd5ab24bec0e50875894e95237ee984a79d14ccd4aa26c7716463a108c19b43c9f3d01001858689a6e84785dd6d483115c12414b2bb036e144c7835526f3af4015a7fbae6a330132\",\"pi_a\":[\"03843386aec7850f08f08b17a18cff3748122d9cd2877679eece405259b338781c55da9608ffcb460ead65109126e48f\",\"03ad0362e7d6c16eeed0f015063aa652d5f43b6ae4b720909a0bc675ff2d3d0cce15dac73e5e0351e13b71bed3e71063\"],\"pi_b\":[[\"0277d3f0e3cf2ba021774ac36abd3912cc38b81c742ed59d1d8d7959492f84cd62ce07c871f7bdd29e5910bd373ed4b4\",\"14c0ae1d4078b9f9e35a4af96be45481f0ba58433f11b3426dfe8a940f7e86f8f6c09a6b3469db80b313bee5c6c046a7\"],[\"042d5f68eaf965c39c24de1378e6e2bca84dcb57bbd7ece4d9ac27b1f1d1dccf9db9dc7122944483a92d676d9b270289\",\"0befd1a0086445857ac1ac184e2b155cf0a9451de0d4ec8c8ec583bff5d07b32bea8651d14e85bfb198a765ee9c70926\"]],\"pi_c\":[\"09d29505d37d03a32bfc0f611f5811d24f8fa2764b721eb8c1cb7bb94aefae16e66ce575976b17da21b4a1871f6f37f3\",\"0f59c13c01431ca329025cc4c9ebd8c3fa2fec167d1abc2604f40b192f786859f9441f07125db48526c09fc47392ebb3\"],\"public_inputs\":[\"07a76bdb1bacc994bdf46c7540c734b8ca17c063731e47a1aaa2c1bce2d1e067\",\"19738b05d9758d49a8fd66b8606bfa7c1d0b7f58be3276fde17bc05b7f27546d\"]}";

        let proof = crate::ProofWithPublicInputs::<E>::fromjson(proof_json_str);

        let mut vk = crate::VerifyingKey::<E>::fromjson(vk_json_str);


        vk.gamma_abc_g1.push(proof.extra);

        let pvk = prepare_verifying_key(&vk);

        assert_eq!(
            Groth16::<E>::verify_proof(&pvk, proof.proof(), &proof.public_inputs()), Ok(true)
        );
    }
}
