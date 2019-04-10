use std::fmt;
use std::rc::{Rc};
use num_bigint::{BigInt, Sign};
use num_integer::{Integer};
use num_traits::*;
use finite_field::{Field, FieldElement};
use util::{bigint_to_bytes32_be};

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
        // mod allows us to handle negative numbers by:
        //   g^(x) = g^(x+q), so.. g^(-x+q) = g^(q-x) which is the same as: x % q
        let mut coeff = n.clone().into().mod_floor(curve.field_ref().p_ref());
        let mut current = self.clone();
        let mut result = Point::Infinity;

        while coeff > BigInt::zero() {
            if !(&coeff & BigInt::one()).is_zero() {
                result = result.add(&current, curve); // add
            }
            current = current.add(&current, curve); // double
            coeff >>= 1;
        }

        result
    }

    pub fn is_infinity(&self) -> bool {
        self == &Point::Infinity
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

// Standards for Efficient Cryptography (SEC) encoding
pub trait Sec<T, C> where T: Sized, C: Sized {
    fn as_sec(&self) -> Vec<u8>;
    fn as_sec_compressed(&self) -> Vec<u8>;
    fn from_sec<'a>(bytes: &'a [u8], curve: &'a C) -> Result<T, String>;
}

impl Sec<Point, FiniteCurve> for Point {
    fn as_sec(&self) -> Vec<u8> {
        match self {
            Point::Infinity => panic!("cannot encode infinity in sec"),
            Point::Coordinate { x, y } => {
                let mut result = vec![0x04];
                result.append(&mut bigint_to_bytes32_be(&x.value, true));
                result.append(&mut bigint_to_bytes32_be(&y.value, true));
                result
            }
        }
    }

    fn as_sec_compressed(&self) -> Vec<u8> {
        match self {
            Point::Infinity => panic!("cannot encode infinity in sec"),
            Point::Coordinate { x, y } => {
                let mut result = vec![];
                let prefix = if y.is_even() { 2 } else { 3 };
                result.push(prefix);
                result.append(&mut bigint_to_bytes32_be(&x.value, false));
                result
            }
        }
    }

    /// Decode sec encoded bytes into a Point. Supports compressed and uncompressed formats.
    fn from_sec<'a>(bytes: &'a [u8], curve: &'a FiniteCurve) -> Result<Point, String> {
        match bytes[0] {
            2 => { // y is even
                let x = BigInt::from_bytes_be(Sign::Plus, &bytes[1..]);
                let y = curve.solve_y(&x, true);
                Ok(curve.point(x, y))
            },
            3 => { // y is odd
                let x = BigInt::from_bytes_be(Sign::Plus, &bytes[1..]);
                let y = curve.solve_y(&x, false);
                Ok(curve.point(x, y))
            },
            4 => {
                if bytes.len() < 65 {
                    return Err(String::from("Not enough bytes. Expected at least 65"));
                }

                let x = BigInt::from_bytes_be(Sign::Plus, &bytes[1..33]);
                let y = BigInt::from_bytes_be(Sign::Plus, &bytes[33..65]);
                Ok(curve.point(x, y))
            },
            prefix => Err(format!("Invalid prefix: {}", prefix))
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
    fn field_ref(&self) -> &Field;
    fn a_ref(&self) -> &FieldElement;
    fn b_ref(&self) -> &FieldElement;
}

impl FiniteCurvy for FiniteCurve {
    fn field_ref(&self) -> &Field {
        &self.field
    }

    fn a_ref(&self) -> &FieldElement {
        &self.a
    }

    fn b_ref(&self) -> &FieldElement {
        &self.b
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

    pub fn point<T: Into<BigInt>, P: Into<BigInt>>(&self, x: T, y: P) -> Point {
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

    fn solve_y(&self, x: &BigInt, is_even: bool) -> FieldElement {
        // rhs of y^2 = x^3 + ax + 7
        let x_3 = self.field_elem(x.pow(3 as u8));
        let rhs = x_3 + &self.a*x + &self.b;
        let y = rhs.sqrt();

        // TODO: Understand these conditionals better since it seems like we never use the case
        // that is calculated?
        let (even_beta, odd_beta) = if y.is_even() {
            (y.clone(), self.field_elem(self.field.p_ref() - &y.value))
        } else {
            (self.field_elem(self.field.p_ref() - &y.value), y.clone())
        };

        if is_even {
            even_beta
        } else {
            odd_beta
        }
    }

    /// Determine whether or not the provided point is on the curve by evaluating the curve
    /// equation
    pub fn is_valid_point(&self, point: &Point) -> bool {
        match &point {
            Point::Infinity => false,
            Point::Coordinate { x, y } => {
                let lhs = y.pow(&BigInt::from(2));
                let rhs = x.pow(&BigInt::from(3)) + self.a_ref() * x + self.b_ref();
                lhs == rhs
            },
        }
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

    #[test]
    fn elliptic_curve_sec() {
        let c = &FiniteCurve::new(2, 3, 97);
        let p = c.point(1, 2);

        let sec = p.as_sec();

        let expected: &[u8] = &[
            // prefix
            4,
            // x
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
            // y
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2
        ];
        assert_eq!(sec, expected.to_vec());
    }

    #[test]
    fn elliptic_curve_sec_compressed() {
        let c = &FiniteCurve::new(2, 3, 97);

        assert_eq!(c.point(1, 2).as_sec_compressed(), vec![2, 1]);
        assert_eq!(c.point(1, 3).as_sec_compressed(), vec![3, 1]);
    }

    #[test]
    fn elliptic_curve_from_sec() {
        // p = 99, so that p % 4 = 3
        let c = &FiniteCurve::new(2, 3, 99);
        // Find starting point on curve using x =1.
        // y^2 = x^3 + 2a + b
        // 1 + 2 + 3 = 6, y2 = 6.. y^(p+1)/4 = y^25
        // x = 1, y = 54

        assert_eq!(c.point(1, 54), Point::from_sec(&[
            // prefix
            4,
            // x
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
            // y
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 54
        ], &c).unwrap());

        // Compressed format
        assert_eq!(c.point(1, 54), Point::from_sec(&[2, 1], &c).unwrap());
        assert_eq!(c.point(1, 45), Point::from_sec(&[3, 1], &c).unwrap());
    }
}
