import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

/**
 * Symmetric cryptogram.
 * 
 * @author Minh Ngyen
 */
public class SymmetricCrytogram implements Serializable {
	
	private static final long serialVersionUID = 1L;

	private byte[] z;
	private byte[] c;
	private byte[] t;
	
	/**
	 * Construct a SymmetricCrytogram - initializes contents
	 * 
	 * @param theZ
	 * @param theC
	 * @param theT
	 */
	public SymmetricCrytogram(final byte[] theZ, final byte[] theC, final byte[] theT) {
		z = theZ;
		c = theC;
		t = theT;
	}
	
	/**
	 * Symmetric cryptogram: (z, c, t)
	 */
	public byte[] byteContext() {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		try {
			output.write(z);
			output.write(c);
			output.write(t);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return output.toByteArray();
	}
	
	public byte[] getZ() {
		return z;
	}
	
	public byte[] getC() {
		return c;
	}
	
	public byte[] getT() {
		return t;
	}
}
