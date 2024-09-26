use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG as Params, ParamsVerifierKZG as ParamsVerifier,
};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2curves::ff::PrimeField;
use poseidon_circuit::hash::{PoseidonHashTable, SpongeChip, SpongeConfig};
use poseidon_circuit::poseidon::Pow5Chip;
use poseidon_circuit::DEFAULT_STEP;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

struct TestCircuit(PoseidonHashTable<Fp>, usize);

// test circuit derived from table data
impl Circuit<Fp> for TestCircuit {
    type Config = SpongeConfig<Fp, Pow5Chip<Fp, 3, 2>>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(PoseidonHashTable::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let hash_tbl = [0; 6].map(|_| meta.advice_column());
        let q_enable = meta.fixed_column();
        SpongeConfig::configure_sub(meta, (q_enable, hash_tbl), DEFAULT_STEP)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip =
            SpongeChip::<Fp, DEFAULT_STEP, Pow5Chip<Fp, 3, 2>>::construct(config.clone(), &self.0, self
                .1);
        chip.load(&mut layouter)
    }
}

fn main() {
    let k = 8;

    let params = Params::<Bn256>::unsafe_setup(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let circuit = TestCircuit(
        PoseidonHashTable {
            inputs: vec![
                [
                    Fp::from_str_vartime("1").unwrap(),
                    Fp::from_str_vartime("2").unwrap(),
                ],
                [
                    Fp::from_str_vartime("30").unwrap(),
                    Fp::from_str_vartime("1").unwrap(),
                ],
                [Fp::from_str_vartime("65536").unwrap(), Fp::zero()],
            ],
            controls: vec![0, 46, 14],
            ..Default::default()
        },
        4,
    );

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        os_rng,
        &mut transcript,
    )
        .unwrap();

    let proof_script = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier_params().clone();
    let strategy = SingleStrategy::new(&params);
    let circuit = TestCircuit(PoseidonHashTable::default(), 4);
    let vk = keygen_vk(&params, &circuit).unwrap();

    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &verifier_params,
            &vk,
            strategy,
            &[&[]],
            &mut transcript
        )
            .is_ok()
    );
}
