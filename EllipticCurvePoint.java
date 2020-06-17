import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * The implementation of an Elliptic Curve Point P = (Px, Py).
 * Elliptic curves: sets of plane points (x, y) that satisfy a mixed equation
 * of form 𝑦2 =𝑥3+𝑎𝑥+𝑏.
 * Given two points 𝑥1, 𝑦1 and 𝑥2, 𝑦2 on an elliptic curve, in general the points 𝑥1 + 𝑥2, 𝑦2 + 𝑦2 or
 * 𝑥1𝑥2, 𝑦2𝑦2 are not on the curve.
 * 
 * @author Minh Nguyen
 *
 */
public class EllipticCurvePoint implements Serializable {
	
	private static final long serialVersionUID = 4721945048807566658L;

	/**
	 * p ≔ 2521 − 1, a Mersenne prime.
	 */
	public static final BigInteger MERESNNE_PRIME = (new BigInteger("2").pow(251)).subtract(BigInteger.ONE);
	
	private BigInteger myX;
	private BigInteger myY;
	
	public static final BigInteger D = new BigInteger("-376014");
	
	
	/**
	 * Construct an elliptic curve point from given (x, y).
	 * 
	 * @param x
	 * @param y
	 */
	public EllipticCurvePoint(final BigInteger x, final BigInteger y) {
		myX = x;
		myY = y;
	}
	
	/**
	 * Construct a neutral point O = (0, 1).
	 */
	public EllipticCurvePoint() {
		this(BigInteger.ZERO, BigInteger.ONE);
	}
	
	/**
	 * Constructor for a curve point from its 𝑥 coordinate and the least significant bit of y.
	 * 
	 * y = +/- sqrt((1 - x^2) / (1 + 376014x^2)) mod p
	 */
	public EllipticCurvePoint(final BigInteger theX, boolean lsb) {
		// (1 - x^2)
		BigInteger numerator = BigInteger.ONE.subtract(theX.pow(2));
		
		// (1 + 376014x^2)
		BigInteger denominator = BigInteger.ONE.add((new BigInteger("376014")).multiply(theX.pow(2)));
		
		// (1 - x^2) / (1 + 376014x^2)
		BigInteger n_d = numerator.divide(denominator);
		
		//  sqrt((1 - x^2) / (1 + 376014x^2))
		BigInteger sqRoot = sqrt(n_d, MERESNNE_PRIME, lsb);
				
		myX = theX;
		myY = sqRoot.mod(MERESNNE_PRIME);;
	}
	
	/**
	 * Opposite of a point (x, y) is the point (-x, y).
	 */
	public EllipticCurvePoint oppositePoint(final BigInteger x, final BigInteger y) {
		return new EllipticCurvePoint(x.multiply(new BigInteger("-1")), y);
	}
	
	/** Compare points for equality.
	 * 
	 * @param p1 Elliptic Curve Point
	 * @param p2 Elliptic Curve Point
	 * @return whether p1 = p2
	 */
	public boolean isEqualPoint(final EllipticCurvePoint p1, final EllipticCurvePoint p2) {
		return p1.myX.equals(p2.myX) && p1.myY.equals(p2.myY);
	}
	
	/**
	 * Given any two points (𝑥1, 𝑦1) and (𝑥2, 𝑦2) on the curve 𝐸521, 
	 * their sum is the point (𝑥1, 𝑦1) + (𝑥2, 𝑦2) = (𝑥1𝑦2+𝑦1𝑥2 / 1+𝑑𝑥1𝑥2𝑦1𝑦2, 𝑦1𝑦2−𝑥1𝑥2 / 1−𝑑𝑥1𝑥2𝑦1𝑦2). 
	 * @param p2 is the other point
	 * @return sum of the points
	 */
	public EllipticCurvePoint sumOfPoints(final EllipticCurvePoint p2) {
		BigInteger x1 = this.myX;
		BigInteger y1 = this.myY;
		BigInteger x2 = p2.getX();
		BigInteger y2 = p2.getY();
		
		BigInteger numeratorX = (x1.multiply(y2)).add((y1.multiply(x2)));
		BigInteger denomX = BigInteger.ONE.add((D.multiply(x1).multiply(x2).multiply(y1).multiply(y2)));
		BigInteger numeratorY = (y1.multiply(y2)).subtract((x1.multiply(x2)));
		BigInteger denomY = (BigInteger.ONE.subtract((D.multiply(x1).multiply(x2).multiply(y1).multiply(y2))));
		
		return new EllipticCurvePoint(modInverse(numeratorX, denomX), modInverse(numeratorY, denomY));
	}
	
	/**
	 * "Exponentiation" algorithm (elliptic curve version).
	 */
	public static EllipticCurvePoint multiplyPoint(BigInteger s, EllipticCurvePoint G) {
		// get binary string of s
		String x = s.toString(2);			//x=(xk, xk-1, ... , x1, x0)2, xk = 1
		int k = x.length();
		EllipticCurvePoint Y = G;			// Y <- G
		
		// for i <- k – 1 to 0 by -1:
		for (int i = k - 1; i >= 0; i--) {
			Y = Y.sumOfPoints(Y);				// Y <- Y + Y
			if (x.charAt(i) == '1') {			// if xi == 1: Y <- Y + G
				Y = Y.sumOfPoints(G);
			}
		}
		return Y;							// Y = x * G
	}
	
	/**
	* Compute a square root of v mod p with a specified
	* least significant bit, if such a root exists.
	* 
	* Credit: given in project specification.
	* 
	* @param v the radicand.
	* @param p the modulus (must satisfy p mod 4 = 3).
	* @param lsb desired least significant bit
	* @return a sqrt r of v mod p with r mod 2 = 1 iff lsb = true if such a root
	* exists, otherwise null.
	*/
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
		assert (p.testBit(0) && p.testBit(1)); 		// p = 3 mod 4
		if (v.signum() == 0) {
			return BigInteger.ZERO;
		}
		
		BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
		if (r.testBit(0) != lsb) {
			r = p.subtract(r);		// correct the lsb
		}
		return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}

	/**
	 * Getter for x.
	 */
	public BigInteger getX() {
		return myX;
	}
	
	/**
	 * Getter for y.
	 */
	public BigInteger getY() {
		return myY;
	}
	
	/**
	 * Modular inverse.
	 * 
	 * @param top
	 * @param bot
	 * @return modular inverse with MERESNNE_PRIME.
	 */
	private BigInteger modInverse(BigInteger top, BigInteger bot) {
		return top.multiply(bot.modInverse(MERESNNE_PRIME)).mod(MERESNNE_PRIME);
	}
	
	/**
	 * Write the given elliptic key to file.
	 * Credit: 
	 * https://mkyong.com/java/how-to-read-and-write-java-object-to-a-file/
	 * 
	 * @param Key
	 */
	public static void writeKeyToFile(EllipticCurvePoint Key) {
		try {
			FileOutputStream f = new FileOutputStream(new File("GENERATED_PUBLIC_KEY"));
			ObjectOutputStream o = new ObjectOutputStream(f);
			
			// Write key to file
			o.writeObject(Key);
			
			o.close();
			f.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Read an elliptic key from a file.
	 */
	public static EllipticCurvePoint readKeyFromFile(final String fileName) {
		EllipticCurvePoint key = null;
		try {
		FileInputStream fi = new FileInputStream(new File(fileName));
		ObjectInputStream oi = new ObjectInputStream(fi);
		
		// Read key 
		key = (EllipticCurvePoint) oi.readObject();
		
		fi.close();
		oi.close();
		
		} catch (Exception e) {
			e.printStackTrace();
		}
		return key;
	}
}
