use std::fmt;
use std::rc::{Rc};
use num_bigint::{BigInt};
use num_traits::*;
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

    pub fn add(&self, q: &Point, curve: &FiniteCurvy) -> Point {
        let p = self;
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
                    (x_p2 * BigInt::from(3) + curve.a_ref()) / (y_p * BigInt::from(2))
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

    // Multiplication implemented using the double-and-add algorithm.
    //
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
    pub fn mul<T: Into<BigInt> + Clone>(&self, n: &T, curve: &FiniteCurvy) -> Point {
        let mut coeff = n.clone().into();
        let mut current = self.clone();
        let mut result = Point::Infinity;

        if coeff < BigInt::zero() {
            panic!("Unexpected multiply by negative number");
        }

        while coeff > BigInt::zero() {
            if !(&coeff & BigInt::one()).is_zero() {
                result = result.add(&current, curve); // add
            }
            current = current.add(&current, curve); // double
            coeff >>= 1;
        }
        result
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Point::Infinity => write!(f, "(inf, inf)"),
            Point::Coordinate { x, y } => write!(f, "({}, {})", x, y)
        }
    }
}

// Elliptic Curve in Weierstrass normal form: y^2 = x^3 + ax + b
// Defined over F_p
#[derive(Debug, Clone)]
pub struct FiniteCurve {
    a: FieldElement,
    b: FieldElement,
    field: Field
}

pub trait FiniteCurvy {
    fn a_ref(&self) -> &FieldElement;
}

impl FiniteCurvy for FiniteCurve {
    fn a_ref(&self) -> &FieldElement {
        &self.a
    }
}

impl FiniteCurve {
    pub fn new<T: Into<BigInt>>(a: T, b: T, p: T) -> Self {
        let field = Field::new(p);
        FiniteCurve { a: field.elem(a), b: field.elem(b), field }
    }

    pub fn field_elem<T: Into<BigInt>>(&self, n: T) -> FieldElement {
        self.field.elem(n)
    }

    pub fn point<T: Into<BigInt>>(&self, x: T, y: T) -> Point {
        let (x, y) = (self.field_elem(x.into()), self.field_elem(y.into()));
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

    pub fn with(&self, point: &Point) -> CurveOperation {
        CurveOperation::new(point.clone(), self.clone())
    }
}

#[derive(Debug)]
pub struct CurveOperation {
    pub value: Point,
    curve: Rc<FiniteCurve>
}

impl CurveOperation {
    fn new(value: Point, curve: FiniteCurve) -> Self {
        CurveOperation { value, curve: Rc::new(curve)  }
    }

    pub fn add(&self, q: &Point) -> CurveOperation {
        let new_point = self.value.add(q, self.curve.as_ref());
        CurveOperation { value: new_point, curve: self.curve.clone() }
    }

    pub fn mul<T: Into<BigInt> + Clone>(&self, n: &T) -> CurveOperation {
        let new_point = self.value.mul(n, self.curve.as_ref());
        CurveOperation { value: new_point, curve: self.curve.clone() }
    }
}

impl fmt::Display for CurveOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl PartialEq<Point> for CurveOperation {
    fn eq(&self, rhs: &Point) -> bool {
        &self.value == rhs
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::*;

    #[test]
    fn elliptic_curve_point_add() {
        let c = &FiniteCurve::new(-7, 10, 999999);
        assert_eq!(c.point(1, 2).add(&c.point(1, -2), c), Point::Infinity); // add to inverse
        assert_eq!(c.point(1, 2).add(&Point::Infinity, c), c.point(1, 2)); // add to infinity
        assert_eq!(Point::Infinity.add(&c.point(1, 2), c), c.point(1, 2)); // add to infinity
        assert_eq!(c.point(1, 2).add(&c.point(3, 4), c), c.point(-3, 2)); // add to another
        assert_eq!(c.point(-1, 4).add(&c.point(1, 2), c), c.point(1, -2)); // add to another
        assert_eq!(c.point(1, 2).add(&c.point(1, 2), c), c.point(-1, -4)); // add to self
    }

    #[test]
    fn elliptic_curve_point_mul() {
        let c = &FiniteCurve::new(2, 3, 97);

        let res = c.point(3, 6).mul(&2, c);
        let exp = c.point(80, 10);
        println!("res: {}, exp: {}, add: {}", res, exp, c.point(3, 6).add(&c.point(3, 6), c));
        assert_eq!(res, exp);
    }

    #[test]
    fn elliptic_curve_point_ops() {
        let c = &FiniteCurve::new(-7, 10, 999999);

        let out = c.with(&c.point(1, 2)).add(&c.point(1, -2));
        assert_eq!(out, Point::Infinity); // add to inverse
    }
}
