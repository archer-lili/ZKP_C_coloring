use rand::seq::SliceRandom;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct RandomPermutation(pub Vec<u32>);

impl RandomPermutation {
    pub fn generate(n: usize, rng: &mut impl Rng) -> Self {
        let mut values: Vec<u32> = (0..n as u32).collect();
        values.shuffle(rng);
        RandomPermutation(values)
    }
}

pub fn random_permutation(n: usize) -> Vec<u32> {
    let mut rng = rand::rng();
    RandomPermutation::generate(n, &mut rng).0
}
