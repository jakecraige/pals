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

#[cfg(test)]
mod tests {
    use ecc::{Curve, Point};

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
