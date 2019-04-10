use std::fmt;
use std::rc::{Rc};
use std::ops::{Add, Sub, Mul};
use num_bigint::{BigInt};
use finite_field::{Field, FieldElement};
use elliptic_curve::{FiniteCurve, FiniteCurvy, Point as ECPoint, CurveOperation, Sec};
use util::{sha256_bigint};

#[derive(Debug, Clone)]
pub struct Secp256k1 {
    curve: FiniteCurve,
    pub g: ECPoint,
    subgroup_field: Field
}

impl Secp256k1 {
    /// P value of the Finite Field used in Secp256k1
    pub fn p() -> BigInt {
        let hex = b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        BigInt::parse_bytes(hex, 16).unwrap()
    }

    /// Order n of the subgroup used by the base generator
    pub fn n() -> BigInt {
        let hex = b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        BigInt::parse_bytes(hex, 16).unwrap()
    }

    pub fn new() -> Self {
        let a = BigInt::from(0);
        let b = BigInt::from(7);
        let x_g = BigInt::parse_bytes(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16).unwrap();
        let y_g = BigInt::parse_bytes(b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16).unwrap();

        let curve = FiniteCurve::new(a, b, Secp256k1::p());
        let g = curve.point(x_g, y_g);

        Secp256k1 { curve, g, subgroup_field: Field::new(Secp256k1::n()) }
    }

    // Produce the public key from a provided private key. Helper method to provide more semantic
    // API to caller.
    pub fn pubkey(&self, private_key: &BigInt) -> Point {
        let point = self.curve.mul(&self.g, private_key);
        Point::new(point, self.clone())
    }

    // Create field element within the field on the order of curve
    pub fn field_elem<T: Into<BigInt>>(&self, n: T) -> FieldElement {
        self.curve.field_elem(n)
    }

    // Create field element within the field on the order of the subgroup
    pub fn subgroup_field_elem(&self, n: BigInt) -> FieldElement {
        self.subgroup_field.elem(n)
    }

    pub fn with(&self, p: &ECPoint) -> CurveOperation {
        self.curve.with(p)
    }

    pub fn g(&self) -> Point {
        Point::new(self.g.clone(), self.clone())
    }

    pub fn is_valid_point(&self, point: &Point) -> bool {
        self.curve.is_valid_point(point.point_ref())
    }

    /// Intended to hash arbitrary content onto the curve using SHA-256. This works the first time
    /// for some content but not all so it's not safe to call with arbitrary strings since it
    /// doesn't retry to find.
    pub fn hash_onto_curve(&self, content: &[u8]) -> Point {
        let x = self.field_elem(sha256_bigint(content));
        // RHS calculation here stolen from: https://github.com/bbuenz/provisions/blob/b51530db630bc5bddf30bbae0f3d5c99a755649a/src/main/java/edu/stanford/crypto/ECConstants.java#L29-L31
        let rhs = x.pow(&BigInt::from(2)) * (self.a_ref() + x.clone()) + self.b_ref();
        let y = rhs.sqrt();
        let ec_point = self.curve.point(x.value.clone(), y.value);
        let point = Point::new(ec_point, self.clone());
        assert!(self.is_valid_point(&point), "point is not on curve");

        point
    }
}

impl FiniteCurvy for Secp256k1 {
    fn field_ref(&self) -> &Field {
        self.curve.field_ref()
    }

    fn a_ref(&self) -> &FieldElement {
        self.curve.a_ref()
    }

    fn b_ref(&self) -> &FieldElement {
        self.curve.b_ref()
    }
}

#[derive(Debug, Clone)]
pub struct Point {
    point: ECPoint,
    curve: Rc<Secp256k1>
}

impl Point {
    fn new(point: ECPoint, curve: Secp256k1) -> Point {
        Point { point, curve: Rc::new(curve) }
    }

    /// Return a new instance of the point at infinity
    pub fn infinity() -> Point {
        let curve = Secp256k1::new();
        Point { point: ECPoint::Infinity, curve: Rc::new(curve) }
    }

    pub fn point_ref(&self) -> &ECPoint {
        &self.point
    }

    pub fn inverse(&self) -> Point {
        self.new_from_ec_point(self.point.inverse())
    }

    /// Helper method to create a new point cloning the existing curve over
    pub fn new_from_ec_point(&self, point: ECPoint) -> Point {
        Point { point, curve: self.curve.clone() }
    }

    /// Return the coordinates of the point iff it is not the point at infinity.
    pub fn as_coord(&self) -> Option<(&FieldElement, &FieldElement)> {
        match &self.point {
            ECPoint::Infinity => None,
            ECPoint::Coordinate { x, y } => Some((x, y))
        }
    }
}

impl Sec<Point, Secp256k1> for Point {
    fn as_sec(&self) -> Vec<u8> { self.point.as_sec() }
    fn as_sec_compressed(&self) -> Vec<u8> { self.point.as_sec_compressed() }

    fn from_sec<'a>(bytes: &'a [u8], curve: &'a Secp256k1) -> Result<Point, String> {
        let point = ECPoint::from_sec(bytes, &curve.curve)?;
        Ok(Point::new(point, curve.clone()))
    }
}

impl PartialEq<Point> for Point {
    fn eq(&self, rhs: &Point) -> bool {
        &self.point == &rhs.point
    }
}

impl PartialEq<ECPoint> for Point {
    fn eq(&self, rhs: &ECPoint) -> bool {
        &self.point == rhs
    }
}

impl Add for Point {
    type Output = Point;

    fn add(self, rhs: Point) -> Point {
        self + &rhs
    }
}

impl<'a> Add<&'a Point> for Point {
    type Output = Point;

    fn add(self, rhs: &'a Point) -> Point {
        &self + rhs
    }
}

impl<'a, 'b> Add<&'b Point> for &'a Point {
    type Output = Point;

    fn add(self, rhs: &'b Point) -> Point {
        let new_point = self.point.add(&rhs.point, self.curve.as_ref());
        self.new_from_ec_point(new_point)
    }
}

impl Sub for Point {
    type Output = Point;

    fn sub(self, rhs: Point) -> Point {
        self - &rhs
    }
}

impl<'a> Sub<&'a Point> for Point {
    type Output = Point;

    fn sub(self, rhs: &'a Point) -> Point {
        // Subtration is defined as adding to the inverse
        let new_point = self.point.add(&rhs.point.inverse(), self.curve.as_ref());
        self.new_from_ec_point(new_point)
    }
}

impl<T: Into<BigInt> + Clone> Mul<T> for Point {
    type Output = Point;

    fn mul(self, n: T) -> Point {
        &self * n
    }
}

impl<'a, T: Into<BigInt> + Clone> Mul<T> for &'a Point {
    type Output = Point;

    fn mul(self, n: T) -> Point {
        let new_point = self.point.mul(&n, self.curve.as_ref());
        self.new_from_ec_point(new_point)
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.point.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use num_traits::*;
    use secp256k1::*;
    use elliptic_curve::{Point as ECPoint, Sec};

    #[test]
    fn secp() {
        // https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
        let test_vectors = vec![
            ("1",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
            ("2",
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
            "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
            ("3",
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
            ("4",
            "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13",
            "51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922"),
            ("5",
            "2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
            "D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6"),
            ("6",
            "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556",
            "AE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297"),
            ("7",
            "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
            "6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA"),
            ("8",
            "2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01",
            "5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904"),
            ("9",
            "ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE",
            "CC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37"),
            ("10",
            "A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7",
            "893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7"),
            ("11",
            "774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB",
            "D984A032EB6B5E190243DD56D7B7B365372DB1E2DFF9D6A8301D74C9C953C61B"),
            ("12",
            "D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A",
            "A9F34FFDC815E0D7A8B64537E17BD81579238C5DD9A86D526B051B13F4062327"),
            ("13",
            "F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8",
            "0AB0902E8D880A89758212EB65CDAF473A1A06DA521FA91F29B5CB52DB03ED81"),
            ("14",
            "499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4",
            "CAC2F6C4B54E855190F044E4A7B3D464464279C27A3F95BCC65F40D403A13F5B"),
            ("15",
            "D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E",
            "581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58"),
            ("16",
            "E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A",
            "F7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821"),
            ("17",
            "DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            "4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77"),
            ("18",
            "5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC",
            "C136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F5192E5E8B061D58"),
            ("19",
            "2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C",
            "85E89BC037945D93B343083B5A1C86131A01F60C50269763B570C854E5C09B7A"),
            ("20",
            "4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97",
            "12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3A"),
            ("112233445566778899",
            "A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29",
            "5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76"),
            ("112233445566778899112233445566778899",
            "E5A2636BCFD412EBF36EC45B19BFB68A1BC5F8632E678132B885F7DF99C5E9B3",
            "736C1CE161AE27B405CAFD2A7520370153C2C861AC51D6C1D5985D9606B45F39"),
            ("28948022309329048855892746252171976963209391069768726095651290785379540373584",
            "A6B594B38FB3E77C6EDF78161FADE2041F4E09FD8497DB776E546C41567FEB3C",
            "71444009192228730CD8237A490FEBA2AFE3D27D7CC1136BC97E439D13330D55"),
            ("57896044618658097711785492504343953926418782139537452191302581570759080747168",
            "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63",
            "3F3979BF72AE8202983DC989AEC7F2FF2ED91BDD69CE02FC0700CA100E59DDF3"),
            ("86844066927987146567678238756515930889628173209306178286953872356138621120752",
            "E24CE4BEEE294AA6350FAA67512B99D388693AE4E7F53D19882A6EA169FC1CE1",
            "8B71E83545FC2B5872589F99D948C03108D36797C4DE363EBD3FF6A9E1A95B10"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494317",
            "4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97",
            "ED45D9234EF13E9DA259E05EF57BB3989E9D6B7D8E269698BAFD77106DCC1FF5"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494318",
            "2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C",
            "7A17643FC86BA26C4CBCF7C4A5E379ECE5FE09F3AFD9689C4A8F37AA1A3F60B5"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494319",
            "5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC",
            "3EC93E23F34146CF161D67FBCA76CAE27E271F438C951D5E0AE6D1A074F9DED7"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494320",
            "DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            "BDEE54F96B9CAE9716684F152D56C251312E0B5FB56A3F09304E660861A910B8"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494321",
            "E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A",
            "081CAF8C661A6A6D624660CB0A86C8EFED6976E1BB2DC0F41E0CD330969E940E"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494322",
            "D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E",
            "A7E1D78D57938D597C7BD13DD733921015BF50D427692C5A3AFB235F095D90D7"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494323",
            "499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4",
            "353D093B4AB17AAE6F0FBB1B584C2B9BB9BD863D85C06A4339A0BF2AFC5EBCD4"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494324",
            "F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8",
            "F54F6FD17277F5768A7DED149A3250B8C5E5F925ADE056E0D64A34AC24FC0EAE"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494325",
            "D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A",
            "560CB00237EA1F285749BAC81E8427EA86DC73A2265792AD94FAE4EB0BF9D908"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494326",
            "774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB",
            "267B5FCD1494A1E6FDBC22A928484C9AC8D24E1D20062957CFE28B3536AC3614"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494327",
            "A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7",
            "76C545BDABE643D85C4938196C5DB3969086B3D127885EA6C3411AC3FC8C9358"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494328",
            "ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE",
            "33CC76DE4F5826029BC7F68E89C49E165227775BC8A071F0FA33D9D439B05FF8"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494329",
            "2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01",
            "A3B25758BEAC66B6D6C2F7D5ECD2EC4B3D1DEC2945A489E84A25D3479342132B"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494330",
            "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
            "951435BF45DAA69F5CE8729279E5AB2457EC2F47EC02184A5AF7D9D6F78D9755"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494331",
            "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556",
            "51ED8885530449DF0C4169FE80BA3A9F217F0F09AE701B5FC378F3C84F8A0998"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494332",
            "2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
            "2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494333",
            "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13",
            "AE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494334",
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "C77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BD"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494335",
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
            "E51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705"),
            ("115792089237316195423570985008687907852837564279074904382605163141518161494336",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777")
        ];


        let curve = Secp256k1::new();
        for (sk, sx, sy) in test_vectors {
            let k = BigInt::from_str(sk).unwrap();
            let expected_x = BigInt::from_str_radix(sx, 16).unwrap();
            let expected_y = BigInt::from_str_radix(sy, 16).unwrap();

            let pubk = curve.g() * k;
            let (x, y) = pubk.as_coord().expect("not infinity");
            assert_eq!(x.value.to_str_radix(16), expected_x.to_str_radix(16));
            assert_eq!(y.value.to_str_radix(16), expected_y.to_str_radix(16));
        }
    }

    #[test]
    fn secp_sec_encoding() {
        let values = vec![
            (
                BigInt::from(5000),
                b"\x04\xff\xe5X\xe3\x88\x85/\x01 \xe4j\xf2\xd1\xb3p\xf8XT\xa8\xeb\x08A\x81\x1e\xce\x0e>\x03\xd2\x82\xd5|1]\xc7(\x90\xa4\xf1\n\x14\x81\xc01\xb0;5\x1b\r\xc7\x99\x01\xca\x18\xa0\x0c\xf0\t\xdb\xdb\x15z\x1d\x10",
                b"\x02\xff\xe5X\xe3\x88\x85/\x01 \xe4j\xf2\xd1\xb3p\xf8XT\xa8\xeb\x08A\x81\x1e\xce\x0e>\x03\xd2\x82\xd5|"
            ),
            (
                BigInt::from(2018).pow(5 as usize),
                b"\x04\x02\x7f=\xa1\x91\x84U\xe0<F\xf6Y&j\x1b\xb5 N\x95\x9d\xb76M/G;\xdf\x8f\n\x13\xcc\x9d\xff\x87d\x7f\xd0#\xc1;JI\x94\xf1v\x91\x89X\x06\xe1\xb4\x0bW\xf4\xfd\"X\x1aOF\x85\x1f;\x06",
                b"\x02\x02\x7f=\xa1\x91\x84U\xe0<F\xf6Y&j\x1b\xb5 N\x95\x9d\xb76M/G;\xdf\x8f\n\x13\xcc\x9d"
            ),
            (
                BigInt::from(0xdeadbeef12345i64),
                b"\x04\xd9\x0c\xd6%\xee\x87\xdd8em\xd9\\\xf7\x9fe\xf6\x0frs\xb6}0\x96\xe6\x8b\xd8\x1eOSBi\x1f\x84.\xfav/\xd5\x99a\xd0\xe9\x98\x03\xc6\x1e\xdb\xa8\xb3\xe3\xf7\xdc:4\x186\xf9w3\xae\xbf\x98q!",
                b"\x03\xd9\x0c\xd6%\xee\x87\xdd8em\xd9\\\xf7\x9fe\xf6\x0frs\xb6}0\x96\xe6\x8b\xd8\x1eOSBi\x1f"
            )
        ];

        let curve = Secp256k1::new();
        for (secret, uncompressed, compressed) in values {
            let public_key = curve.pubkey(&secret);
            let result = public_key.as_sec();
            assert_eq!(result.len(), 65);
            assert_eq!(result, &uncompressed[..]);

            let decoded = Point::from_sec(&result, &curve);
            assert_eq!(decoded, Ok(public_key.clone()));

            let result = public_key.as_sec_compressed();
            assert_eq!(result.len(), 33);
            assert_eq!(result, &compressed[..]);

            let decoded = Point::from_sec(&result, &curve);
            assert_eq!(decoded, Ok(public_key.clone()));
        }
    }

    #[test]
    fn secp256k1_point_add() {
        let c = &Secp256k1::new();

        assert_eq!(c.g() + c.g().inverse(), ECPoint::Infinity); // add to inverse
        assert_eq!(c.g() + Point::infinity(), c.g()); // add to infinity
        assert_eq!(c.g() - c.g(), ECPoint::Infinity); // sub value
    }

    #[test]
    fn secp256k1_point_mul() {
        let c = &Secp256k1::new();

        assert_eq!(c.g() * 0, ECPoint::Infinity);
        assert_eq!(c.g() * 1, c.g());
    }

    #[test]
    fn secp256k1_hash_onto_curve() {
        let c = &Secp256k1::new();

        let point = c.hash_onto_curve(b"PROVISIONS");

        assert!(c.is_valid_point(&point), "it generates a valid point");
    }
}
