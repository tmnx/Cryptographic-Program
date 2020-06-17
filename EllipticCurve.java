import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class EllipticCurve {
	
	/**
	 * A point on e521 with x = 4 and y an even number.
	 */
	private static final EllipticCurvePoint G = new EllipticCurvePoint(new BigInteger("4"), new BigInteger("0"));
	
	/**
	 * Prevent instantiation of this object.
	 */
	private EllipticCurve() {
		// DO NOTHING
	}
	
	/**
	 * Generate a (Schnorr/ECDHIES) key pair (s, V) from a pass-phrase pw.
	 * Then, write the public key to a file.
	 */
	public static EllipticCurvePoint generateKeyPair(byte[] pw) {
		HASH hashFunction = new HASH();
		// s <- KMACXOF256(pw, “”, 512, “K”); s <- 4s
		BigInteger s = new BigInteger(hashFunction.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes()));
		// s <- 4s
		s = s.multiply(new BigInteger("4"));
		
		// V <- s * G
		EllipticCurvePoint V = EllipticCurvePoint.multiplyPoint(s, new EllipticCurvePoint(G.getX(), false));
		
		return V;
	}
	
	/**
	 * Encrypt a byte array m under the (Schnorr/ECDHIES) public key V.
	 * 
	 * @param m message
	 * @param V public key
	 */
	public static EllipticCurveCryptogram encryptWithPublicKey(final byte m[], EllipticCurvePoint V) {
		SecureRandom random = new SecureRandom();
		byte[] z = new byte[64];					// 512 bits (64 bytes)
		random.nextBytes(z); 						
		
		BigInteger k = new BigInteger(z);			// k <- Random(512)
		k = k.multiply(new BigInteger("4")); 		// k <- 4k
		
		EllipticCurvePoint W = EllipticCurvePoint.multiplyPoint(k, V);		// W <- k * V
		EllipticCurvePoint Z = EllipticCurvePoint.multiplyPoint(k, G);		// Z <- k * G
		
		HASH hashFunction = new HASH();
		// (ke || ka) <- KMACXOF256(Wx, “”, 1024, “P”)
		byte[] ke_ka = hashFunction.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
		byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);
		
		// c <- KMACXOF256(ke, "", |m|, "PKE") XOR m
		hashFunction.sha3_reset();
		byte[] c = HASH.xor_byteArrays((hashFunction.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes())), m, m.length);
		
		// t <- KMACXOF256(ka, m, 512, "PKA")
		hashFunction.sha3_reset();
		byte[] t = hashFunction.KMACXOF256(ka, m, 512, "PKA".getBytes());
		
		// cryptogram: (Z, c, t)
		EllipticCurveCryptogram ecc = new EllipticCurveCryptogram(Z, c, t);
		
		return ecc;
	}
	
	/**
	 * Decrypt a cryptogram (Z, c, t) under the pass-phrase pw.
	 */
	public static byte[] decryptWithPW(final EllipticCurveCryptogram ecc, final byte[] pw) {
		HASH hashFunction = new HASH();
		
		BigInteger s = new BigInteger(hashFunction.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes()));
		s = s.multiply(new BigInteger("4"));
		
		EllipticCurvePoint W = EllipticCurvePoint.multiplyPoint(s, new EllipticCurvePoint(ecc.getZ().getX(), false));
		
		hashFunction.sha3_reset();
		byte[] ke_ka = hashFunction.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
		byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);
		
		hashFunction.sha3_reset();
		byte[] m = HASH.xor_byteArrays(hashFunction.KMACXOF256(ke, "".getBytes(), ecc.getC().length * 8, "PKE".getBytes()), ecc.getC(), ecc.getC().length);
		
		hashFunction.sha3_reset();
		byte[] t_prime = hashFunction.KMACXOF256(ka, m, 512, "PKA".getBytes());
		
		// accept if, and only if, t’ = t
        if (!Arrays.equals(ecc.getT(), t_prime)) {
        	System.out.println("The passphrase is INCORRECT!");
        	System.out.println("Cannot decrypt the file.");
        	return null;
        }
        // ELSE
        return m;
	}

}
