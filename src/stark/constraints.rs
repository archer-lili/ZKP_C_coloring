use crate::crypto::polynomial::BlankPolynomial;
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

#[derive(Debug)]
pub enum ConstraintViolation {
    NonBinaryValue(usize, u8),
    InvalidSum { expected: u64, actual: u64 },
    DomainUnavailable,
}

#[derive(Debug, Clone)]
pub struct BlankCountConstraints<F: FftField> {
    pub n: u32,
    pub expected_sum: u64,
    pub n_squared: usize,
    pub domain: Radix2EvaluationDomain<F>,
}

impl<F: FftField> BlankCountConstraints<F> {
    pub fn new(n: u32, expected_sum: u64) -> Self {
        let n_squared = (n as usize).saturating_mul(n as usize).max(1);
        let domain =
            Radix2EvaluationDomain::<F>::new(n_squared.next_power_of_two()).expect("radix2 domain");
        BlankCountConstraints {
            n,
            expected_sum,
            n_squared,
            domain,
        }
    }

    pub fn check(&self, polynomial: &BlankPolynomial) -> Result<(), ConstraintViolation> {
        for idx in 0..polynomial.len() {
            let value = polynomial.evaluate(idx);
            if value > 1 {
                return Err(ConstraintViolation::NonBinaryValue(idx, value));
            }
        }

        let actual_sum = polynomial.sum();
        if actual_sum != self.expected_sum {
            return Err(ConstraintViolation::InvalidSum {
                expected: self.expected_sum,
                actual: actual_sum,
            });
        }

        Ok(())
    }
}
