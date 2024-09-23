use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode}, convert::{ToBitsGadget, ToBytesGadget, ToConstraintFieldGadget}, eq::EqGadget, fields::fp::FpVar, prelude::Boolean, select::{CondSelectGadget, ThreeBitCondNegLookupGadget, TwoBitLookupGadget}, uint8::UInt8, R1CSVar
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, Result as R1CSResult, SynthesisError},
};
use ark_std::{borrow::Borrow, vec::Vec};
use num_bigint::BigUint;

/// The allocated version of `EmulatedFpVar` (introduced below)
#[derive(Debug)]
#[must_use]
pub struct AllocatedEmulatedFpVar<TargetF: PrimeField, BaseF: PrimeField> {
    /// Constraint system reference
    pub cs: ConstraintSystemRef<BaseF>,
    /// value
    pub value: TargetF,
    /// base value
    pub base_value: FpVar<BaseF>,
}

impl<TargetF: PrimeField, BaseF: PrimeField> AllocatedEmulatedFpVar<TargetF, BaseF> {
    /// Return cs
    pub fn cs(&self) -> ConstraintSystemRef<BaseF> {
        self.cs.clone()
    }

    /// Obtain the value of limbs
    pub fn new(cs: ConstraintSystemRef<BaseF>, value: TargetF) -> Self {
        let base_value = value.into_bigint();
        let base_value = BaseF::try_from(base_value.into()).unwrap();
        let base_value = FpVar::<BaseF>::new_witness(ns!(cs, "baseF"), || Ok(base_value)).unwrap();
        Self {
            cs,
            value,
            base_value,
        }
    }

    /// Obtain the value of a emulated field element
    pub fn value(&self) -> R1CSResult<TargetF> {
        Ok(self.value.clone())
    }

    /// Obtain the emulated field element of a constant value
    pub fn constant(cs: ConstraintSystemRef<BaseF>, value: TargetF) -> R1CSResult<Self> {
        let base_value = value.into_bigint();
        let base_value = BaseF::try_from(base_value.into()).unwrap();
        let base_value = FpVar::<BaseF>::new_witness(ns!(cs, "baseF"), || Ok(base_value))?;
        Ok(Self {
            cs,
            value,
            base_value,
        })
    }

    /// Obtain the emulated field element of one
    pub fn one(cs: ConstraintSystemRef<BaseF>) -> R1CSResult<Self> {
        Self::constant(cs, TargetF::one())
    }

    /// Obtain the emulated field element of zero
    pub fn zero(cs: ConstraintSystemRef<BaseF>) -> R1CSResult<Self> {
        Self::constant(cs, TargetF::zero())
    }

    /// modulus on BaseF
    fn modulus(&self) -> BaseF {
        BaseF::try_from(TargetF::MODULUS.into()).unwrap()
    }

    /// Add a emulated field element
    pub fn add(&self, other: &Self) -> R1CSResult<Self> {
        let self_val: BigUint = self.value.into_bigint().into();
        let other_val: BigUint = other.value.into_bigint().into();
        let modulus: BigUint = TargetF::MODULUS.into();
        let result = self_val + other_val;
        let quotient = &result / &modulus;
        let reminder = &result % &modulus;

        let quotient = BaseF::from_bigint(BaseF::BigInt::try_from(quotient).unwrap()).unwrap();
        let reminder = BaseF::from_bigint(BaseF::BigInt::try_from(reminder).unwrap()).unwrap();

        // (quentient * MODUUS + reminder) % base_modulus = (self_val + other_val)
        // % base_modulus reminder = (self_val + other_val) % MODUUS
        let quotient_var = FpVar::<BaseF>::new_witness(self.cs(), || Ok(quotient)).unwrap();
        let reminder_var = FpVar::<BaseF>::new_witness(self.cs(), || Ok(reminder)).unwrap();

        let lhs = &self.base_value + &other.base_value;
        let rhs = quotient_var * self.modulus() + reminder_var;

        lhs.enforce_equal(&rhs).unwrap();

        // todo: rangecheck quotient, reminder

        Ok(Self::new(self.cs.clone(), self.value + other.value))
    }

    /// Add a constant
    pub fn add_constant(&self, other: &TargetF) -> R1CSResult<Self> {
        let other_var = Self::new(self.cs(), other.clone());

        self.add(&other_var)
    }

    /// Subtract a emulated field element, without the final reduction step
    pub fn sub_without_reduce(&self, other: &Self) -> R1CSResult<Self> {
        self.sub(other)
    }

    /// Subtract a emulated field element
    pub fn sub(&self, other: &Self) -> R1CSResult<Self> {
        let neg_other = Self::new(self.cs(), -other.value);
        self.add(&neg_other)
    }

    /// Subtract a constant
    pub fn sub_constant(&self, other: &TargetF) -> R1CSResult<Self> {
        self.sub(&Self::constant(self.cs(), *other)?)
    }

    /// Multiply a emulated field element
    pub fn mul(&self, other: &Self) -> R1CSResult<Self> {
        let self_val: BigUint = self.value.into_bigint().into();
        let other_val: BigUint = other.value.into_bigint().into();
        let modulus: BigUint = TargetF::MODULUS.into();
        let result = self_val * other_val;
        let quotient = &result / &modulus;
        let reminder = &result % &modulus;

        let quotient = BaseF::from_bigint(BaseF::BigInt::try_from(quotient).unwrap()).unwrap();
        let reminder = BaseF::from_bigint(BaseF::BigInt::try_from(reminder).unwrap()).unwrap();

        // (quentient * MODUUS + reminder) % base_modulus = (self_val + other_val)
        // % base_modulus reminder = (self_val + other_val) % MODUUS
        let quotient_var = FpVar::<BaseF>::new_witness(self.cs(), || Ok(quotient)).unwrap();
        let reminder_var = FpVar::<BaseF>::new_witness(self.cs(), || Ok(reminder)).unwrap();

        let lhs = &self.base_value * &other.base_value;
        let rhs = quotient_var * self.modulus() + reminder_var;

        lhs.enforce_equal(&rhs).unwrap();

        // todo: rangecheck quotient, reminder

        Ok(Self::new(self.cs.clone(), self.value * other.value))
    }

    /// Multiply a constant
    pub fn mul_constant(&self, other: &TargetF) -> R1CSResult<Self> {
        self.mul(&Self::constant(self.cs(), *other)?)
    }

    /// Compute the negate of a emulated field element
    #[tracing::instrument(target = "r1cs")]
    pub fn negate(&self) -> R1CSResult<Self> {
        Self::zero(self.cs())?.sub(self)
    }

    /// Compute the inverse of a emulated field element
    #[tracing::instrument(target = "r1cs")]
    pub fn inverse(&self) -> R1CSResult<Self> {
        let inverse = Self::new_witness(self.cs(), || {
            Ok(self.value()?.inverse().unwrap_or_else(TargetF::zero))
        })?;

        let actual_result = self.clone().mul(&inverse)?;
        actual_result.conditional_enforce_equal(&Self::one(self.cs())?, &Boolean::TRUE)?;
        Ok(inverse)
    }

    // /// Convert a `TargetF` element into limbs (not constraints)
    // /// This is an internal function that would be reused by a number of other
    // /// functions
    // pub fn get_limbs_representations(
    //     elem: &TargetF,
    //     optimization_type: OptimizationType,
    // ) -> R1CSResult<Vec<BaseF>> {
    //     Self::get_limbs_representations_from_big_integer(&elem.into_bigint(),
    // optimization_type) }

    // /// Obtain the limbs directly from a big int
    // pub fn get_limbs_representations_from_big_integer(
    //     elem: &<TargetF as PrimeField>::BigInt,
    //     optimization_type: OptimizationType,
    // ) -> R1CSResult<Vec<BaseF>> {
    //     let params = get_params(
    //         TargetF::MODULUS_BIT_SIZE as usize,
    //         BaseF::MODULUS_BIT_SIZE as usize,
    //         optimization_type,
    //     );

    //     // push the lower limbs first
    //     let mut limbs: Vec<BaseF> = Vec::new();
    //     let mut cur = *elem;
    //     for _ in 0..params.num_limbs {
    //         let cur_bits = cur.to_bits_be(); // `to_bits` is big endian
    //         let cur_mod_r = <BaseF as PrimeField>::BigInt::from_bits_be(
    //             &cur_bits[cur_bits.len() - params.bits_per_limb..],
    //         ); // therefore, the lowest `bits_per_non_top_limb` bits is what we
    // want.         limbs.push(BaseF::from_bigint(cur_mod_r).unwrap());
    //         cur >>= params.bits_per_limb as u32;
    //     }

    //     // then we reserve, so that the limbs are ``big limb first''
    //     limbs.reverse();

    //     Ok(limbs)
    // }

    pub(crate) fn frobenius_map(&self, _power: usize) -> R1CSResult<Self> {
        Ok(self.clone())
    }

    pub(crate) fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<BaseF>,
    ) -> R1CSResult<()> {
        // Get delta = self - other
        let cs = self.cs().or(other.cs()).or(should_enforce.cs());
        let mut delta = self.sub(other)?;
        delta = should_enforce.select(&delta, &Self::zero(cs.clone())?)?;

        Ok(())
    }

    pub(crate) fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<BaseF>,
    ) -> R1CSResult<()> {
        let cs = self.cs().or(other.cs()).or(should_enforce.cs());

        let _ = should_enforce
            .select(&self.sub(other)?, &Self::one(cs)?)?
            .inverse()?;

        Ok(())
    }

    // pub(crate) fn get_optimization_type(&self) -> OptimizationType {
    //     match self.cs().optimization_goal() {
    //         OptimizationGoal::None => OptimizationType::Constraints,
    //         OptimizationGoal::Constraints => OptimizationType::Constraints,
    //         OptimizationGoal::Weight => OptimizationType::Weight,
    //     }
    // }

    /// Allocates a new variable, but does not check that the allocation's limbs
    /// are in-range.
    fn new_variable_unchecked<T: Borrow<TargetF>>(
        cs: impl Into<Namespace<BaseF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> R1CSResult<Self> {
        let ns = cs.into();
        let cs = ns.cs();

        Ok(Self::new(cs, f()?.borrow().clone()))
    }

    /// Check that this element is in-range; i.e., each limb is in-range, and
    /// the whole number is less than the modulus.
    ///
    /// Returns the bits of the element, in little-endian form
    fn enforce_in_range(&self, cs: impl Into<Namespace<BaseF>>) -> R1CSResult<Vec<Boolean<BaseF>>> {
        unimplemented!()
    }

    /// Allocates a new non-native field witness with value given by the
    /// function `f`.  Enforces that the field element has value in `[0,
    /// modulus)`, and returns the bits of its binary representation.
    /// The bits are in little-endian (i.e., the bit at index 0 is the LSB) and
    /// the bit-vector is empty in non-witness allocation modes.
    pub fn new_witness_with_le_bits<T: Borrow<TargetF>>(
        cs: impl Into<Namespace<BaseF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> R1CSResult<(Self, Vec<Boolean<BaseF>>)> {
        unimplemented!()
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> ToBitsGadget<BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    #[tracing::instrument(target = "r1cs")]
    fn to_bits_le(&self) -> R1CSResult<Vec<Boolean<BaseF>>> {
        unimplemented!()
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> ToBytesGadget<BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    #[tracing::instrument(target = "r1cs")]
    fn to_bytes_le(&self) -> R1CSResult<Vec<UInt8<BaseF>>> {
        unimplemented!()
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> CondSelectGadget<BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    #[tracing::instrument(target = "r1cs")]
    fn conditionally_select(
        cond: &Boolean<BaseF>,
        true_value: &Self,
        false_value: &Self,
    ) -> R1CSResult<Self> {
        unimplemented!()
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> TwoBitLookupGadget<BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    type TableConstant = TargetF;

    #[tracing::instrument(target = "r1cs")]
    fn two_bit_lookup(
        bits: &[Boolean<BaseF>],
        constants: &[Self::TableConstant],
    ) -> R1CSResult<Self> {
        unimplemented!()
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> ThreeBitCondNegLookupGadget<BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    type TableConstant = TargetF;

    #[tracing::instrument(target = "r1cs")]
    fn three_bit_cond_neg_lookup(
        bits: &[Boolean<BaseF>],
        b0b1: &Boolean<BaseF>,
        constants: &[Self::TableConstant],
    ) -> R1CSResult<Self> {
        unimplemented!()
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> AllocVar<TargetF, BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    fn new_variable<T: Borrow<TargetF>>(
        cs: impl Into<Namespace<BaseF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> R1CSResult<Self> {
        let ns = cs.into();
        let cs = ns.cs();
        let this = Self::new_variable_unchecked(ns!(cs, "alloc"), f, mode)?;
        // if mode == AllocationMode::Witness {
        //     this.enforce_in_range(ns!(cs, "bits"))?;
        // }
        Ok(this)
    }
}

impl<TargetF: PrimeField, BaseF: PrimeField> ToConstraintFieldGadget<BaseF>
    for AllocatedEmulatedFpVar<TargetF, BaseF>
{
    fn to_constraint_field(&self) -> R1CSResult<Vec<FpVar<BaseF>>> {
        unimplemented!()
    }
}

// Implementation of a few traits

impl<TargetF: PrimeField, BaseF: PrimeField> Clone for AllocatedEmulatedFpVar<TargetF, BaseF> {
    fn clone(&self) -> Self {
        AllocatedEmulatedFpVar {
            cs: self.cs(),
            value: self.value.clone(),
            base_value: self.base_value.clone(),
        }
    }
}
