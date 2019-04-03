use num_traits::*;
use num_bigint::{BigInt};
use finite_field::{Field, FieldElement};

#[derive(Debug, PartialEq, Clone)]
pub enum Point {
    Infinity,
    Coordinate { x: FieldElement, y: FieldElement }
}

impl Point {
    pub fn coord(x: FieldElement, y: FieldElement) -> Point {
        Point::Coordinate { x, y }
    }

    pub fn inverse(&self) -> Point {
        match self.clone() {
            Point::Infinity => Point::Infinity,
            Point::Coordinate { x, y } => Point::Coordinate { x, y: -y },
        }
    }
}

// Elliptic Curve in Weierstrass normal form: y^2 = x^3 + ax + b
// Defined over F_p
#[derive(Debug)]
pub struct FiniteCurve {
    a: FieldElement,
    b: FieldElement,
    field: Field
}

impl FiniteCurve {
    pub fn new(a: BigInt, b: BigInt, p: BigInt) -> Self {
        let field = Field::new(p);
        FiniteCurve { a: field.elem(a), b: field.elem(b), field }
    }

    pub fn field_elem(&self, n: BigInt) -> FieldElement {
        self.field.elem(n)
    }

    pub fn point(&self, x: BigInt, y: BigInt) -> Point {
        let (x, y) = (self.field_elem(x), self.field_elem(y));
        // TODO: Verify point on curve
        Point::coord(x, y)
    }

    // P + -P = 0
    // P + 0 = P = 0 + P
    // P + Q = -R
    pub fn add(&self, p: &Point, q: &Point) -> Point {
        if p == &q.inverse() {
            return Point::Infinity;
        }

        match (p, q) {
            (Point::Infinity, _) => q.clone(),
            (_, Point::Infinity) => p.clone(),

            (Point::Coordinate {x: x_p, y: y_p}, Point::Coordinate {x: x_q, y: y_q}) => {
                // We now have two non-zero, non-symmetric points to work with
                let m = if x_p == x_q && y_p == y_p {
                    let x_p2 = x_p * x_p;
                    // Slope calculation is different when points are equal
                    (x_p2 * BigInt::from(3) + &self.a) / (y_p * BigInt::from(2))
                } else {
                    (y_p - y_q) / (x_p - x_q)
                };

                // Intersection of points
                let m2 = &m * &m;
                let x_r = m2 - x_p - x_q;
                let y_r = y_q + (m * (&x_r - x_q));

                // (x_p, y_p) + (x_q, y_q) = (x_r, -y_r)
                Point::Coordinate { x: x_r, y: -y_r }
            }
        }
    }

    pub fn mul(&self, p: &Point, n: &BigInt) -> Point {
        let mut coeff = n.clone();
        let mut current = p.clone();
        let mut result = Point::Infinity;

        if n < &BigInt::zero() {
            panic!("Unexpected multiply by negative number");
        }

        while coeff > BigInt::zero() {
            if !(&coeff % BigInt::from(2)).is_zero() {
                result = self.add(&current, &result);
            }
            current = self.add(&current, &current);
            coeff >>= 1;
        }
        result
    }
}
