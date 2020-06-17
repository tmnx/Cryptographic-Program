import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.SecureRandom;
import java.util.Arrays;

/*
 * Cryptography Practical Project
 */

/**
 * The Java implementation of SHA-3 (KECCAK[512]) and the derived SHAKE256
 * inspired by the C implementation of Markku-Juhani O. Saarinen <mjos@iki.fi>
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * & by  Valerie Peng
 * 
 * This implementation also includes cSHAKE256 and KMACXOF256 based off of
 * NIST SP 800-185: https://doi.org/10.6028/NIST.SP.800-185
 * 
 * The implementation also include symmetric encryption / decryption.
 * 
 * NOTE: some of the helper methods implementations are from other sources (cited
 * 		 in the method documentation - see below for links).
 * 
 * @author Minh Nguyen
 * @author Markku-Juhani O. Saarinen
 * @author Valerie Peng
 */
public class HASH {
    
    /**
	 * The number of rounds (KECCAK-p permuntation).
	 */
	private static final int ROUNDS = 24;
	
	/**
	 * Width in bytes (200 bytes = 1600 bits)
	 */
    private static final int WIDTH = 200;
    
    /**
     * Dimension of lanes.
     */
    private static final int DM = 5;

    /**
	 * Predefined set of 24 values that specifies how many bytes to shift on each round.
	 * This is needed in the Iota step.
	 */
    private static final long[] ROUND_CONSTANTS = 	
    		{0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
    		 0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
    		 0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
    		 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
    		 0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
    		 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
    		 0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
    		 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    
    /**
	 * A set of rotation constants.
	 */
    private static final int[] ROTATION_CONSTANTS = 
    	{1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    	 27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

    private static final int[] PILN =
		{10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
		 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
    
    
	// State contexts for SHA3
	private byte[] b;
	private long[] q;
    private int pt;
    private int rsiz;
    private int mdlen;
    
	/**
	 * Constructor - Initialize state context for Sha3
	 */
	public HASH() {
		b = new byte[WIDTH];
		for (int i = 0; i <= ROUNDS; i++) {
			b[i] = (byte)0;
		}
		q = new long[25];	
		pt = 0;
		mdlen = 32;
		rsiz = WIDTH - 2 * mdlen;
	}

	/**
	 * ----Mappings----
	 * Apply the function Keccak-f permutation that is consist of 24 rounds.
	 * Each round consists of sequence of 5 steps: theta, rho, pi, chi, iota.
	 * Each step manipulates the entire state.
	 * 
	 * Method based off of the C implementation of Markku-Juhani O. Saarinen.
	 * 
	 * @param st the state array.
	 * 
	 */
	private void keccakf(byte[] st) {												// copy of state array but in long type
		long[] bc = new long[DM];
		long t;

		// Endianess conversion. This is redundant on little-endian targets
		
		for (int i = 0; i <= ROUNDS; i++) {
			   for (int j = 0; j < 8; j++) {
				   q[i] |= (((long)st[i * 8 + j] & 0xFFL) << (j * 8));
			   }
		}

		// actual iteration
		// ------- Apply rounds -------
		for (int round = 0; round < ROUNDS; round++) {

			// Theta
			for (int i = 0; i < DM; i++) {
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10] ^ q[i + 15] ^ q[i + 20];
            }
			for (int i = 0; i < DM; i++) {
				t = bc[(i + 4) % DM] ^ ROTL64(bc[(i + 1) % DM], 1);
				for (int j = 0; j <= ROUNDS; j += DM) {
					q[j + i] ^= t;
				}
			}

			// Rho Pi
			t = q[1];
			for (int i = 0; i < ROUNDS; i++) {
				int j = PILN[i];
				bc[0] = q[j];
				q[j] = ROTL64(t, ROTATION_CONSTANTS[i]);
				t = bc[0];
			}

			//  Chi
			for (int j = 0; j <= ROUNDS; j += 5) {
				for (int i = 0; i < 5; i++) {
                    bc[i] = q[j + i];
                }
				for (int i = 0; i < 5; i++) {
                    q[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
			}

			//  Iota
			q[0] ^= ROUND_CONSTANTS[round];
		}

		// Little-Edian conversion.
		for (int i = 0; i <= ROUNDS; i++) {
			// copy term in A' for conversion
			t = q[i];
			for (int j = 0; j < 8; j++) {
				st[i * 8 + j] = (byte)((t >>  (j * 8)) & 0xFF);
			}
		}
	}

    /**
     * Update state with more data.
     * 
     * Method based off of the C implementation of Markku-Juhani O. Saarinen.
     * 
     * @param data
     * @param len
     */
    private void sha3_update(byte[] data, int len) {
		int j = pt;
		
		for (int i = 0; i < len; i++) {
			b[j++] ^= data[i];
			if (j >= rsiz) {
				keccakf(b);
				q = new long[25];
				j = 0;
			}
		}
		pt = j;
	}
    
    /**
     * Finalize and output a hash.
     * 
     * Method based off of the C implementation of Markku-Juhani O. Saarinen.
     */
    private void sha3_final() {
    	b[pt] ^= 0x06;
    	b[rsiz] ^= 0x80;
    	keccakf(b);
    }
    
    /**
     * Compute a SHA-3 hash of given byte length from "in"
     * 
     * Method based off of the C implementation of Markku-Juhani O. Saarinen.
     * 
     * @param in
     * @return hashed output
     */
    public byte[] compute_sha3(byte[] in) {
    	sha3_update(in, in.length);
    	sha3_final();
    	
    	return b;
    }
    
    /**
     * Reset Sha-3 state contexts.
     */
    public void sha3_reset() {
		b = new byte[WIDTH];
		for (int i = 0; i <= ROUNDS; i++) {
			b[i] = (byte)0;
		}
		q = new long[25];	
		pt = 0;
		mdlen = 32;
		rsiz = WIDTH - 2 * mdlen;
    }
    
    ///////////// SHAKE 256 extensible-output functionality /////////////////
    
    // Method based off of the C implementation of Markku-Juhani O. Saarinen.
    private void shake_xof() {
    	// SHAKE256(M, d) = KECCAK[512] (M || 1111, d).
    	// suffix = 0x1F
    	b[pt] ^= 0x1F;
		b[rsiz - 1] ^= 0x80;
		keccakf(b);
		q = new long[25];
		this.pt = 0;
	}

    // Method based off of the C implementation of Markku-Juhani O. Saarinen.
    private void shake_out(byte[] out, int len) {
		int j = pt;
		for (int i = 0; i < len; i++) {
			if (j >= rsiz) {
				keccakf(b);
				q = new long[25];
				j = 0;
			}
			out[i] = b[j++];
		}
		pt = j;
	}
    
    
    private void cshake_xof() {
    	// suffix = 0x04
    	b[pt] ^= 0x04;
		b[this.rsiz - 1] ^= 0x80;
		keccakf(b);
		q = new long[25];
		this.pt = 0;
    }

	/**
	 * The cSHAKE256 is a customizable SHAKE function that provides a 256-bit 
	 * security length.
	 * 
	 * NIST SP 800-185: https://doi.org/10.6028/NIST.SP.800-185
	 * 
	 * @param X the main input bit string of any length, including zero.
	 * @param L an integer representing the requested output length in bits.
	 * @param N a string of a function name. When no function other than cSHAKE is desired, 
	 * 		  N is set to the empty string.
	 * @param S an input string to allow users to customize their use of the function.
	 * 		  When no customization is desired, S is set to the empty string.
	 */
    public byte[] cSHAKE256(final byte[] X, final int L, final String N, final byte[] S) {
    	int len = L >>> 3;
    	byte[] out = new byte[len];
    	
    	// if N = "" && S= "" return SHAKE256(X, L)
    	if (N == "" && S == null) {
    		sha3_update(X, X.length);
    		shake_xof();
    		shake_out(out, len);
    	} 
    	
    	// else return KECCAK[512]
    	else {
        	// KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)
    		byte[] data = bytepad(combineArrays(encode_string(N.getBytes()), encode_string(S)), 136);
    		sha3_update(data, data.length);
    		sha3_update(X, X.length);
    		cshake_xof();
    		shake_out(out, len);
    	}
    	
        return out;
    }

	/**
	 * The KECCAK Message Authentication Code.
	 * 
	 * NIST SP 800-185: https://doi.org/10.6028/NIST.SP.800-185
	 * 
	 * @param K a key bit string of any length, including zero
	 * @param X the main input bit string of any length, including zero
	 * @param L an integer representing the requested output length in bits.
	 * @param S an optional customization bit string of any length, including zero. 
	 * 		  If no customization is desired, S is set to the empty string.
	 */
    public byte[] KMACXOF256(final byte[] K, final byte[] X, final int L, final byte[] S) { 	
    	byte[] bytepadded = bytepad(encode_string(K), 136);
    	byte[] right_enc = right_encode(0);
    	
    	// newX = bytepad(encode_string(K), 136) || X || right_encode(0)
    	byte[] newX = combineArrays(bytepadded, X);
    	newX = combineArrays(newX, right_enc);
    			
    	// return cSHAKE256(newX, L, “KMAC”, S)
    	return cSHAKE256(newX, L, "KMAC", S);
    }
    
    /**
     * Encrypt a given symmetric crytogram under a given pass-phrase
     * 
     * @param m content byte array
     * @param pw passphrase
     */
    public SymmetricCrytogram encryptSymmetrically(final byte[] m, final byte[] pw) {
    	 final SecureRandom random = new SecureRandom();
    	 final byte[] z = new byte[64];		// 512 bits (64 bytes)
    	 random.nextBytes(z);				// z <- Random(512)
    	 
    	 // (ke || ka) <- KMACXOF256(z || pw, "", 1024, "S")
    	 sha3_reset();
    	 byte[] ke_ka = KMACXOF256(combineArrays(z, pw), "".getBytes(), 1024, "S".getBytes());
    	 byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
    	 byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);
    	 
    	 // c <- KMACXOF256(ke, “”, |m|, “SKE”) xor m (output length must be multiple of 8 (L))
    	 sha3_reset();
    	 byte[] c = xor_byteArrays(KMACXOF256(ke, "".getBytes(), m.length * 8, "SKE".getBytes()), m, m.length);
    	 
    	 // t <- KMACXOF256(ka, m, 512, “SKA”)
    	 sha3_reset();
    	 byte[] t = KMACXOF256(ka, m, 512, "SKA".getBytes());
    	 
    	 // symmetric cryptogram: (z, c, t)
    	 SymmetricCrytogram sc = new SymmetricCrytogram(z, c, t);
    	 return sc;
    }
    
    /**
     * Decrypt a given symmetrically cryptogram (z, c, t) under a given passphrase.
     */
    public byte[] decryptSymmetrically(SymmetricCrytogram sc, byte[] pw) throws IOException {
        // Get z, c, t
        byte[] z = sc.getZ();
        byte[] t = sc.getT();
        byte[] c = sc.getC();

        // (ke || ka) <- KMACXOF256(z || pw, "", 1024, "S")
        sha3_reset();
        byte[] ke_ka = KMACXOF256(combineArrays(z, pw), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Arrays.copyOfRange(ke_ka, ke_ka.length / 2, ke_ka.length);
        
        // m <- KMACXOF256(ke, “”, |c|, “SKE”) XOR c
        sha3_reset();
        byte[] m = xor_byteArrays(KMACXOF256(ke, "".getBytes(), c.length * 8, "SKE".getBytes()), c, c.length);

        // t' <- KMACXOF256(ka, m, 512, “SKA”)
        sha3_reset();
        byte[] t_prime = KMACXOF256(ka, m, 512, "SKA".getBytes());
        
        // accept if, and only if, t’ = t
        if (!Arrays.equals(t, t_prime)) {
        	System.out.println("The passphrase is INCORRECT!");
        	System.out.println("Cannot decrypt the file.");
        	return null;
        }
        // ELSE
        return m;
    }

    /////// HELPER METHODS /////////
    
	/**
	 * Left rotate:
	 * Rotate the bits of a lane by a length (offset) which depends on the fixed
	 * X and Y coordinates of the lane.
	 * 
	 * Method based off of the C implementation of Markku-Juhani O. Saarinen.
	 * 
	 * @param theX the X coordinate of the lane.
	 * @param theY the Y coordinate of the lane.
	 * 
	 * @return the rotated bits.
	 */
	private static long ROTL64(final long theX, final long theY) {
		return (((theX) << (theY)) | ((theX) >>> (64 - (theY))));
	}
	
	/**
	 * Encode the integer X as a byte string in a way that can be unambiguously parsed 
	 * from the beginning of the string by inserting the length of the byte string before
	 * the byte string representation of X.
	 * 
	 * Validity condition: 0 <= x < 2^2040 (infinity)
	 * 
	 * https://crypto.stackexchange.com/questions/75269/sha3-the-left-right-encode-functions
	 * 
	 * Example: left_encode(0) will yield 10000000 00000000
	 * 
	 * @param x the integer to be encoded.
	 * 
	 * @return a byte string
	 */
    private static byte[] left_encode(int x) {
    	byte[] O  = {(byte)0x01, (byte)0x00};
    	if (x == 0) {
    		return O;
    	}
    	
    	// ELSE
    	int n = 1;
    	while (!(Math.pow(2,  (8 * n)) > x)) {
    		n++;
    	}
    	O = new byte[n + 1];
    	for (int i = n; i > 0; i--) {
    		O[i] = (byte)(x & 0xFF);
    		x >>>= 8;
    	}
    	O[0] = (byte)n;
    	return O;	
    }
	
	/**
	 * Encode the integer X as a byte string in a way that can be unambiguously parsed 
	 * from the end of the string by inserting the length of the byte string after the 
	 * byte string representation of X.
	 * 
	 * right_encode(0) will yield 00000000 10000000

	 * @return a byte string
	 */
	private static byte[] right_encode(int x) {
		byte[] O = {(byte)0x00, (byte)0x01};		// "00000000 00000001"
		if (x == 0) { 			
			return O;
		}
		// ELSE
		int n = 1;
		while (!(Math.pow(2, (8 * n)) > x)) {
			n++;
		}
		O = new byte[n + 1];
		for (int i = n - 1; i > -1; i--) {
			O[i] = (byte)(x & 0xFF);
			x >>>= 8;
		}
		O[O.length - 1] = (byte)n;
		return O;
	}
	
	/**
	 * Encode bit strings in a way that may be parsed unambiguously from the beginning 
	 * of the string S.
	 * 
	 * As an example, encode_string(S) where S is the empty string "" 
	 * will yield 10000000 00000000.
	 * 
	 * @param S bit string
	 * 
	 * @return bit string
	 */
    private static byte[] encode_string(byte[] S) {
		int S_length = S.length;
		byte[] lenS = {(byte)0x01, (byte)0x00};
		if (S_length != 0) {
			lenS = left_encode(S_length << 3);
		}
		// return left_encode(len(S)) || S)
		return combineArrays(lenS, S);
    }
    
	/**
	 * The bytepad(X, w) function prepends an encoding of the integer w 
	 * to an input string X, then pads the result with zeros until it is a byte string 
	 * whose length in bytes is a multiple of w.
	 * 
	 * @param X an input bit string
	 * @param W a multiple
	 * 
	 * @return 
	 */
    private static byte[] bytepad(final byte[] X, final int w) {
		// Validity condition
		if (w > 0) {
			byte[] encodedW = left_encode(w);
			byte[] z = new byte[w * ((encodedW.length + X.length + w - 1) / w)];
			System.arraycopy(encodedW, 0, z, 0, encodedW.length);
	        System.arraycopy(X, 0, z, encodedW.length, X.length);
	        
			// while (len(z)/8) mod w ≠ 0:		z = z || 00000000
			int i = X.length + encodedW.length;
			while (i < z.length) {
				z[i] = (byte)0;
				i++;
			}
			
			return z;
		}
		throw new IllegalArgumentException("Validity condition not met; "
											+ "w is not greater than zero.");
    }

	/**
	 * Concatenate 2 arrays.
	 * 
	 * Credit: 
	 * https://www.programiz.com/java-programming/examples/concatenate-two-arrays
	 * 
	 * @param a array 1
	 * @param b array 2
	 * @return concatenated array
	 */
	private static byte[] combineArrays(final byte[] theA, final byte[] theB) {
		int lenA = 0;
		int lenB = 0;
		if (theA != null) {
			lenA = theA.length;
		}
		if (theB != null) {
			lenB = theB.length;
		}
		byte[] result = new byte[lenA + lenB];
		System.arraycopy(theA, 0, result, 0, lenA);
		System.arraycopy(theB, 0, result, lenA, lenB);		
		return result;
	}
	
    /**
     * XOR 2 byte arrays.
     * 
     * @param array_1 byte array
     * @param array_2 byte array
     * @return array_1 xor array_2
     */
    public static byte[] xor_byteArrays(byte[] a1, byte[] a2, int len) {
    	byte[] result = new byte[len];
    	
    	int i = 0;
    	for(byte c : a1) {
    		result[i] = (byte)(c ^ a2[i++]);
    	}
    	return result;
    }
	
	/**
	 * Convert a byte array to hex string.
	 * 
	 * Credit: https://mkyong.com/java/java-how-to-convert-bytes-to-hex/
	 */
	public static String convertBytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		
		for (byte bt : bytes) {
			int d = (int)bt & 0xFF;
			String hex = Integer.toHexString(d);
			result.append(hex);
		}
		
		return result.toString();
	}
	
	/**
	 * Read a Cryptogram object from the given file path and return it.
	 * 
	 * https://examples.javacodegeeks.com/core-java/io/file/how-to-read-an-object-from-file-in-java/
	 * 
	 * @param filePath
	 * @return Symmetric Cryptogram object
	 */
	public static Object readCryptogramFromFile(String filePath) {
		try {
			FileInputStream fileIn = new FileInputStream(filePath);
			ObjectInputStream objectIn = new ObjectInputStream(fileIn);
			Object obj = objectIn.readObject();
			objectIn.close();
			return obj;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
