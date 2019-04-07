use std::ops::{Add, Sub, Mul, Div, Neg};
use std::fmt;
use std::mem;
use num_traits::*;
use num_integer::{Integer};
use num_bigint::{BigInt};

/// Returns a three-tuple (gcd, x, y) such that
/// a * x + b * y == gcd, where gcd is the greatest
/// common divisor of a and b.
///
/// This function implements the extended Euclidean
/// algorithm and runs in O(log b) in the worst case.
fn extended_euclidean_algorithm(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    let mut s = BigInt::zero();
    let mut old_s = BigInt::one();

    let mut t = BigInt::zero();
    let mut old_t = BigInt::one();

    let mut r = b;
    let mut old_r = a;

    while !r.is_zero() {
        let quotient = &old_r / &r;

        old_r -= &quotient * &r;
        mem::swap(&mut old_r, &mut r);

        old_s -= &quotient * &s;
        mem::swap(&mut old_s, &mut s);

        old_t -= &quotient * &t;
        mem::swap(&mut old_t, &mut t);
    }

    (old_r, old_s, old_t)
}

/// Finite field over p
#[derive(Debug, PartialEq, Clone)]
pub struct Field {
    p: BigInt
}

impl Field {
    pub fn new<T: Into<BigInt>>(p: T) -> Field {
        Field { p: p.into() }
    }

    /// Return an element in the field
    pub fn elem<T: Into<BigInt>>(&self, value: T) -> FieldElement {
        FieldElement::new(value.into(), self.p.clone())
    }

    pub fn p_ref(&self) -> &BigInt {
        &self.p
    }
}

/// Value within Field F_p
#[derive(Debug, PartialEq, Clone)]
pub struct FieldElement {
    pub value: BigInt,
    p: BigInt
}

impl FieldElement {
    fn new(value: BigInt, p: BigInt) -> FieldElement {
        FieldElement { value: value.mod_floor(&p), p }
    }

    /// Find the multiplicative inverse for x, s.t. x * ? = 1
    pub fn inverse(&self) -> FieldElement {
        let (gcd, x, y) = extended_euclidean_algorithm(self.value.clone(), self.p.clone());
        if (&self.value * &x + &self.p * y).mod_floor(&self.p) != gcd {
            panic!("AHHH");
        }

        if !gcd.is_one() { // Either n is 0, or p is not a prime number.
            panic!("{} has no multiplicative inverse modulo {}", self.value, self.p);
        }

        FieldElement::new(x, self.p.clone())
    }

    // Fermat's little theorem states: n**(p-1) = 1
    // Thus the inverse can be calculated like so:
    //   n**(-1) * 1 = n**(-1) * n**(p-1) = n**(p-2)
    //
    // This is significantly slower than the method using the extended euclidean algoritm but added
    // here for documentation purposes.
    fn slow_inverse(&self) -> FieldElement {
        let mut inv: BigInt = BigInt::one();
        for _ in num_iter::range(BigInt::zero(), &self.p - BigInt::from(2)) {
            inv = (inv * &self.value).mod_floor(&self.p);
        }

        FieldElement::new(inv, self.p.clone())
    }

    pub fn is_even(&self) -> bool {
        &self.value & BigInt::one() == BigInt::zero()
    }

    pub fn pow(&self, n: &BigInt) -> FieldElement {
        let val = self.value.modpow(n, &self.p);
        FieldElement::new(val, self.p.clone())
    }

    // Only works on curves where: p % 4 = 3
    // Derived from fact that p % 4 = 3 and a^(p-1) = 1 which gives us:
    //
    // w^2 = v (we know v and are looking for w)
    // w^2 = w^2 * 1 = w^2 * w^(p-1) = w^(p+1)
    // w^(2/2) = w^(p+1)/2
    // w = w^(p+1)/2
    // w = w^2(p+1)/4 = (w^2)^(p+1)/4 = v^(p+1)/4 = w
    pub fn sqrt(&self) -> FieldElement {
        let exp = (&self.p + 1) / 4;
        self.pow(&exp)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Into<BigInt> for FieldElement {
    fn into(self) -> BigInt {
        self.value
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: FieldElement) -> FieldElement {
        self + &rhs
    }
}

impl<'a> Add<FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn add(self, mut rhs: FieldElement) -> FieldElement {
        rhs.value = (rhs.value + &self.value).mod_floor(&rhs.p);
        rhs
    }
}

impl<'a> Add<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: &'a FieldElement) -> FieldElement {
        let value = (self.value + &rhs.value).mod_floor(&rhs.p);
        FieldElement { value, p: rhs.p.clone() }
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: FieldElement) -> FieldElement {
        self - &rhs
    }
}

impl<'a> Sub<&'a FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: &'a FieldElement) -> FieldElement {
        let value = (self.value - &rhs.value).mod_floor(&rhs.p);
        FieldElement { value, p: rhs.p.clone() }
    }
}

impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: &'b FieldElement) -> FieldElement {
        self.clone() - rhs
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        let value = (-self.value).mod_floor(&self.p);
        FieldElement { value: BigInt::from(value), p: self.p }
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        let value = (self.value * rhs.value).mod_floor(&rhs.p);
        FieldElement { value: BigInt::from(value), p: rhs.p }
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &'b FieldElement) -> FieldElement {
        let value = (&self.value * &rhs.value).mod_floor(&rhs.p);
        FieldElement { value: BigInt::from(value), p: rhs.p.clone() }
    }
}

impl Mul<BigInt> for FieldElement {
    type Output = Self;

    fn mul(mut self, rhs: BigInt) -> Self::Output {
        self.value = (self.value * rhs).mod_floor(&self.p);
        self
    }
}

impl<'a> Mul<&'a BigInt> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &'a BigInt) -> Self::Output {
        self * rhs.clone()
    }
}

impl<'a> Mul<BigInt> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: BigInt) -> Self::Output {
        self * &rhs
    }
}

impl<'a, 'b> Mul<&'b BigInt> for &'a FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &'b BigInt) -> Self::Output {
        self.clone() * rhs
    }
}

impl Div for FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: FieldElement) -> FieldElement {
        self * rhs.inverse()
    }
}

impl PartialEq<usize> for FieldElement {
    fn eq(&self, rhs: &usize) -> bool {
        self.value == BigInt::from(rhs.clone())
    }
}

#[cfg(test)]
mod tests {
    use finite_field::*;

    #[test]
    fn field_element_initialization() {
        let field = Field::new(7);

        // It reduces value mod p when created
        assert_eq!(field.elem(5), 5);
        assert_eq!(field.elem(9), 2);
        assert_eq!(field.elem(-4), 3);
    }

    #[test]
    fn field_element_inverse() {
        let field = Field::new(7);
        let elem = field.elem(254);

        assert_eq!(elem.clone() * elem.inverse(), 1); // valid inverse
        assert_eq!(elem.inverse(), elem.slow_inverse()); // both versions work
    }

    #[test]
    fn field_element_math() {
        let f = Field::new(7);

        assert_eq!(f.elem(5) + &f.elem(5), 3);
        assert_eq!(&f.elem(5) + f.elem(-7), 5);
        assert_eq!(f.elem(5) - &f.elem(5), 0);
        assert_eq!(&f.elem(5) - &f.elem(5), 0);
        assert_eq!(-f.elem(5), 2);
        assert_eq!(f.elem(5) * f.elem(5), 4);
        assert_eq!(&f.elem(2) * &f.elem(2), 4);
        assert_eq!(f.elem(5) * BigInt::from(2), 3);
        // division is lhs * rhs.inverse(). By using the same value we use the definition of the
        // multiplicative inverse and know the answer should be 1.
        assert_eq!(f.elem(3) / f.elem(BigInt::from(3)), 1);
    }

    #[test]
    fn field_element_is_even() {
        let f = Field::new(7);

        assert!(f.elem(2).is_even());
        assert!(!f.elem(3).is_even());
    }
}
