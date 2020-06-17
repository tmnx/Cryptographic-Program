import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Cryptogram of the elliptic curve.
 * 
 * @author Minh Nguyen
 */
public class EllipticCurveCryptogram implements Serializable {
	
	private static final long serialVersionUID = 1607499324027114051L;
	
	private EllipticCurvePoint Z;
	private byte[] c;
	private byte[] t;

	public EllipticCurveCryptogram(final EllipticCurvePoint theZ, final byte[] theC, final byte[] theT) {
		Z = theZ;
		c = theC;
		t = theT;
	}
	
	public EllipticCurvePoint getZ() {
		return Z;
	}
	
	public byte[] getC() {
		return c;
	}
	
	public byte[] getT() {
		return t;
	}
	
	/**
	 * Write the given cryptogram to file.
	 * Credit: 
	 * https://mkyong.com/java/how-to-read-and-write-java-object-to-a-file/
	 * 
	 * @param Key
	 */
	public static void writeCryptogramToFile(EllipticCurveCryptogram cryptogram) {
		try {
			FileOutputStream f = new FileOutputStream(new File("ENCRYPTED_CRYPTOGRAM"));
			ObjectOutputStream o = new ObjectOutputStream(f);
			
			// Write key to file
			o.writeObject(cryptogram);
			
			o.close();
			f.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
