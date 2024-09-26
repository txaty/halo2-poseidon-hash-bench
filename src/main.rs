use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG as Params, ParamsVerifierKZG as ParamsVerifier,
};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
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
    let k = 22;
    let calcs = (140*1024)+1;

    let params = Params::<Bn256>::unsafe_setup(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let inputs = (0..calcs - 1)
        .into_iter()
        .map(|i| {
            [
                Fp::from(i as u64),
                Fp::from((i + 1) as u64),
            ]
        })
        .collect::<Vec<_>>();

    let controls = vec![13; calcs - 1];

    let circuit = TestCircuit(
        PoseidonHashTable {
            inputs,
            controls,
            ..Default::default()
        },
        calcs,
    );


    let curr_time = std::time::Instant::now();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    println!("keygen time: {:?}", curr_time.elapsed());


    let curr_time = std::time::Instant::now();
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
    println!("Proof generation time: {:?}", curr_time.elapsed());

    let curr_time = std::time::Instant::now();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier_params().clone();
    let strategy = SingleStrategy::new(&params);
    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &verifier_params,
            &pk.get_vk(),
            strategy,
            &[&[]],
            &mut transcript
        )
            .is_ok()
    );
    println!("Proof verification time: {:?}", curr_time.elapsed());
}
