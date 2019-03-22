use std::ops::{Add, Sub, Mul, Div};

///
/// Modulo that handles negative numbers, works the same as Python's `%`.
///
/// eg: `(a + b).modulo(c)`
///
pub trait ModuloSignedExt {
    fn modulo(&self, n: Self) -> Self;
}

macro_rules! modulo_signed_ext_impl {
    ($($t:ty)*) => ($(
        impl ModuloSignedExt for $t {
            #[inline]
            fn modulo(&self, n: Self) -> Self {
                (self % n + n) % n
            }
        }
    )*)
}
modulo_signed_ext_impl! { i64 }

/// Returns a three-tuple (gcd, x, y) such that
/// a * x + b * y == gcd, where gcd is the greatest
/// common divisor of a and b.
///
/// This function implements the extended Euclidean
/// algorithm and runs in O(log b) in the worst case.
fn extended_euclidean_algorithm(a: i64, b: i64) -> (i64, i64, i64) {
    let mut s = 0;
    let mut old_s = 1;

    let mut t = 1;
    let mut old_t = 0;

    let mut r = b;
    let mut old_r = a;

    let mut quotient;
    let mut tmp;
    while r != 0 {
        quotient = old_r / r;

        tmp = old_r;
        old_r = r;
        r = tmp - (quotient * r);

        tmp = old_s;
        old_s = s;
        s = tmp - (quotient * s);

        tmp = old_t;
        old_t = t;
        t = tmp - (quotient * t);
    }

    (old_r, old_s, old_t)
}

#[derive(Debug, PartialEq, Clone)]
enum Point {
    Infinity,
    Coordinate { x: f64, y: f64 }
}

impl Point {
    fn inverse(&self) -> Point {
        match *self {
            Point::Infinity => Point::Infinity,
            Point::Coordinate { x, y } => Point::Coordinate { x, y: -y },
        }
    }
}

// Elliptic Curve in Weierstrass normal form: y^2 = x^3 + ax + b
#[derive(Debug)]
struct Curve {
    a: f64,
    b: f64
}

impl Curve {
    // P + -P = 0
    // P + 0 = P = 0 + P
    // P + Q = -R
    fn add(&self, p: Point, q: Point) -> Point {
        if p == q.inverse() {
            return Point::Infinity;
        }

        match (p.clone(), q.clone()) {
            (Point::Infinity, _) => q,
            (_, Point::Infinity) => p,

            (Point::Coordinate {x: x_p, y: y_p}, Point::Coordinate {x: x_q, y: y_q}) => {
                // We now have two non-zero, non-symmetric points to work with
                let m = if x_p == x_q && y_p == y_p {
                    // Slope calculation is different when points are equal
                    ((3. * (x_p * x_p)) + self.a) / (2. * y_p)
                } else {
                    (y_p - y_q) / (x_p - x_q)
                };

                // Intersection of points
                let x_r = (m * m) - x_p - x_q;
                let y_r = y_q + (m * (x_r - x_q));

                // (x_p, y_p) + (x_q, y_q) = (x_r, -y_r)
                Point::Coordinate { x: x_r, y: -y_r }
            }
        }
    }

    // Naive implementation. Replace with double-and-add.
    fn naive_mul(&self, p: Point, n: i64) -> Point {
        let mut r = Point::Infinity;
        for _ in 0..n { r = self.add(r, p.clone()); }
        r
    }
}


/// Finite field over p
#[derive(Debug, PartialEq, Clone, Copy)]
struct Field {
    p: i64
}

impl Field {
    fn new(p: i64) -> Field {
        Field { p }
    }

    fn elem(&self, value: i64) -> FieldElement {
        FieldElement::new(value, self.p)
    }
}

/// Value within Field F_p
#[derive(Debug, PartialEq, Clone, Copy)]
struct FieldElement {
    value: i64,
    p: i64
}

impl FieldElement {
    fn new(value: i64, p: i64) -> FieldElement {
        FieldElement { value, p }
    }

    fn inverse(self) -> FieldElement {
        let (gcd, x, y) = extended_euclidean_algorithm(self.value, self.p);
        if (self.value * x + self.p * y).modulo(self.p) != gcd {
            panic!("AHHH");
        }

        if gcd != 1 { // Either n is 0, or p is not a prime number.
            panic!("{} has no multiplicative inverse modulo {}", self.value, self.p);
        }

        FieldElement::new(x.modulo(self.p), self.p)
    }
}

impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: FieldElement) -> FieldElement {
        let value = (self.value + rhs.value).modulo(rhs.p);
        FieldElement { value, ..rhs }
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: FieldElement) -> FieldElement {
        let value = (self.value - rhs.value).modulo(rhs.p);
        FieldElement { value, ..rhs }
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> FieldElement {
        let value = (self.value * rhs.value).modulo(rhs.p);
        FieldElement { value, ..rhs }
    }
}

impl Div for FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: FieldElement) -> FieldElement {
        self * rhs.inverse()
    }
}

#[cfg(test)]
mod tests {
    use ecc::{Curve, Point, Field, extended_euclidean_algorithm};

    #[test]
    fn working_extended_euclidean_algorithm() {
        let (a, b) = (2, 4);
        let (gcd, x, y) = extended_euclidean_algorithm(a, b);
        assert_eq!(a * x + b * y, 2);
    }

    #[test]
    fn ecc_field_element() {
        let f = Field::new(23);
        // addition
        assert_eq!(f.elem(18) + f.elem(9), f.elem(4));
        // subtraction
        assert_eq!(f.elem(7) - f.elem(14), f.elem(16));
        // multiplication
        assert_eq!(f.elem(4) * f.elem(7), f.elem(5));
        // Additive inverse
        assert_eq!(f.elem(-5) + f.elem(0), f.elem(18));
        // Multiplicative inverse
        assert_eq!(f.elem(9) * f.elem(18), f.elem(1));
    }

    fn ecc_field_element_inverse() {
        let f = Field::new(23);

        assert_eq!(f.elem(9).inverse(), f.elem(18));
    }

    #[test]
    fn ecc_add_to_inverse() {
        let curve = Curve { a: -7., b: 10. };
        let p = Point::Coordinate { x: 1., y: 2. };
        let q = Point::Coordinate { x: 1., y: -2. };
        let r = Point::Infinity;

        assert_eq!(curve.add(p, q), r)
    }

    #[test]
    fn ecc_add_to_infinity() {
        let curve = Curve { a: -7., b: 10. };

        let p = Point::Coordinate { x: 1., y: 2. };
        let q = Point::Infinity;
        let r = Point::Coordinate { x: 1., y: 2.};
        assert_eq!(curve.add(p, q), r);

        let p = Point::Infinity;
        let q = Point::Coordinate { x: 1., y: 2. };
        let r = Point::Coordinate { x: 1., y: 2.};
        assert_eq!(curve.add(p, q), r)
    }

    #[test]
    fn ecc_add_to_another() {
        let curve = Curve { a: -7., b: 10. };

        let p = Point::Coordinate { x: 1., y: 2. };
        let q = Point::Coordinate { x: 3., y: 4. };
        let r = Point::Coordinate { x: -3., y: 2.};
        assert_eq!(curve.add(p, q), r);

        let p = Point::Coordinate { x: -1., y: 4. };
        let q = Point::Coordinate { x: 1., y: 2. };
        let r = Point::Coordinate { x: 1., y: -2.};
        assert_eq!(curve.add(p, q), r);
    }

    #[test]
    fn ecc_add_to_self() {
        let curve = Curve { a: -7., b: 10. };

        let p = Point::Coordinate { x: 1., y: 2. };
        let q = Point::Coordinate { x: 1., y: 2. };
        let r = Point::Coordinate { x: -1., y: -4. };
        assert_eq!(curve.add(p, q), r);
    }

    #[test]
    fn ecc_mul_naive() {
        let curve = Curve { a: -3., b: 1. };

        let p = Point::Coordinate { x: 0., y: 1. };
        let n = 2;
        let r = Point::Coordinate { x: 2.25, y: 2.375 };
        assert_eq!(curve.naive_mul(p, n), r);
    }
}
