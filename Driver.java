/*
 * Cryptography Practical Project
 */

import java.awt.FileDialog;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import javax.swing.JFrame;

/**
 * Driver starts a command line interface that offers the following services:
 * 1. Compute a plain cryptographic hash of a given file or a text input.
 * 2. Encrypt a given data file symmetrically under a given passphrase.
 * 	  Decrypt a given symmetric cryptogram under a given passphrase.
 * 3. Generate an elliptic key pair from a given passphrase and
 * 	  write the public key to a file.
 * 4. Encrypt a data file under a given elliptic public key file.
 * 	  Decrypt a given elliptic-encrypted file from a given password.
 * 5. Sign a given file from a given password and write the signature to a file.
 * 	  Verify a given data file and its signature file under a given public key file.
 * 
 * @author Minh Nguyen
 * @version 01192020
 */
public class Driver {
	
	private static Scanner myScanner = new Scanner(System.in);

	/**
	 * The main method that starts the application.
	 * 
	 * @param theArgs is the command-line argument.
	 */
	public static void main(String[] theArgs) {
		
		printMainMenu();
		
		// Prompts for user selection of service
		userSelection();
		
		myScanner.close();
		System.out.println("Exiting the program...");
	}
	
	/**
	 * Prints the main menu.
	 */
	private static void printMainMenu() {
		System.out.println();
		System.out.println("Select one of the following services:");
		System.out.println();
		System.out.println("0) Exit the program.");
		System.out.println("1) [PART 1] - Compute a plain cryptographic hash of a given file.");
		System.out.println("2) [PART 1 BONUS]  - Compute a plain cryptographic hash from user text input.");
		System.out.println();
		System.out.println("3) [PART 2] - Encrypt a file symmetrically under a given passphrase.");
		System.out.println("4) [PART 2] - Decrypt a file symmetrically under a given passphrase.");
		System.out.println("5) [PART 2 BONUS] - Compute an authentication tag of a given file under a given passphrase.");
		System.out.println();
		System.out.println("6) [PART 3] - Generate an elliptic key pair from a given passphrase and write the public key to a file.");
		System.out.println();
		System.out.println("7) [PART 4] - Encrypt a data file under a given elliptic public key file.");
		System.out.println("8) [PART 4] - Decrypt a given elliptic-encrypted file from a given password.");
		System.out.println();
		System.out.println("9) [PART 5] - Sign a given file from a given password and write the signature to a file.");
		System.out.println();
	}
	
	/**
	 * Gets user selection of service.
	 */
	private static void userSelection() {
		// Scan for user input
		System.out.print("Type your selection [then press Enter]: ");
		myScanner = new Scanner(System.in);
		int selection = myScanner.nextInt();
		
		HASH hashFunction;
		SymmetricCrytogram encrypted;
		byte[] msg = null;
		FileDialog dialog;
		String selected;
		
		byte[] M;				// Message
		
		if (selection != 0) {
			switch(selection) {		// decode which selection the user picked
			
			// [PART 1] Compute a plain hash of a given file
			case 1:
				System.out.println();
				System.out.println("Select a file");	
				dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
				dialog.setVisible(true);
				selected = dialog.getFile();
				if (selected != null) {
					try {
						// bit string message
						M = Files.readAllBytes(Paths.get(dialog.getDirectory() + selected));
						hashFunction = new HASH();
						msg = hashFunction.KMACXOF256("".getBytes(), M, 512, "D".getBytes());
						System.out.println("HASH RESULT: " + HASH.convertBytesToHex(msg).toUpperCase());
					} catch (Exception e) {
						e.printStackTrace();
					}
				} else {
					System.out.println("User did not select a file.");
				}
				break;
				
			// [PART 1 BONUS] Compute a plain hash of text input by the user
			case 2:
				myScanner = new Scanner(System.in);
				System.out.println("\nEnter a string: ");
				String string = myScanner.nextLine();
				M = string.getBytes();
				hashFunction = new HASH();
				msg = hashFunction.KMACXOF256("".getBytes(), M, 512, "D".getBytes());
				System.out.println("HASH RESULT: " + HASH.convertBytesToHex(msg).toUpperCase());
				break;
				
			// [PART 2] Encrypt a given file symmetrically under a given pass-phrase
			case 3:
				System.out.println();
				System.out.println("Select a file");
				dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
				dialog.setVisible(true);
				selected = dialog.getFile();
				if (selected != null) {
					try {
						// bit string message
						M = Files.readAllBytes(Paths.get(dialog.getDirectory() + selected));
						hashFunction = new HASH();
						myScanner = new Scanner(System.in);
						System.out.println("Enter a passphrase: ");
						String pw = myScanner.nextLine();
						encrypted = hashFunction.encryptSymmetrically(M, pw.getBytes());
						ObjectOutputStream output = 
								new ObjectOutputStream(
										new FileOutputStream(
												Paths.get(dialog.getDirectory() + selected).toString()));
						output.writeObject(encrypted);
						output.close();
						System.out.println("ENCRYPTED RESULT: " + HASH.convertBytesToHex(encrypted.byteContext()));
						
					} catch (Exception e) {
						e.printStackTrace();
					}
				} else {
					System.out.println("User did not select a file.");
				}
				break;
			
			// [PART 2] Decrypt a given symmetric crytogram under a given pass-phrase
			case 4: 
				System.out.println("Select a file");
				dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
				dialog.setVisible(true);
				selected = dialog.getFile();
				if (selected != null) {
					// get symmetric crytogram object
					encrypted = (SymmetricCrytogram)HASH.readCryptogramFromFile(Paths.get(dialog.getDirectory() + selected).toString());
					hashFunction = new HASH();
					myScanner = new Scanner(System.in);
					System.out.println("Enter a passphrase: ");
					String pw = myScanner.nextLine();
					try {
						msg = hashFunction.decryptSymmetrically(encrypted, pw.getBytes());
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					System.out.println("DECRYPTED MESSAGE HAS BEEN SAVED TO OUTPUT.TXT");
					// write to new output file of decrypted message
					File output = new File("output.txt");
					Path path = Paths.get(output.getName());
					try {
						Files.write(path, msg);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				break;
				
			// [PART 2 BONUS] Compute an authentication tag of a given file under a given pass-phrase
			case 5:
				System.out.println("Select a file");

				dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
				dialog.setVisible(true);
				selected = dialog.getFile();
				if (selected != null) {
					// bit string message
					try {
						M = Files.readAllBytes(Paths.get(dialog.getDirectory() + selected));
						// get pass-phrase
						myScanner = new Scanner(System.in);
						System.out.println("Enter a passphrase: ");
						String pw = myScanner.nextLine();
						
						// t <- KMACXOF256(pw, m, 512, “T”)
						hashFunction = new HASH();
						byte[] t = hashFunction.KMACXOF256(pw.getBytes(), M, 512, "T".getBytes());
						System.out.println("Athentication tag: " + HASH.convertBytesToHex(t).toUpperCase());
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else {
					System.out.println("User did not select a file.");
				}
				break;
			
			// [PART 3] Generate an elliptic key pair from a given pass-phrase and write the public key to a file
			case 6:
				myScanner = new Scanner(System.in);
				System.out.println("Enter a passphrase: ");
				String pw = myScanner.nextLine();
				
				EllipticCurvePoint V = EllipticCurve.generateKeyPair(pw.getBytes());
				EllipticCurvePoint.writeKeyToFile(V);
				System.out.println("The public key has been saved to the file GENERATED_PUBLIC_KEY in local source file");
				break;
				
			// [PART 4] Encrypt a data file under a given elliptic public key file
			case 7:
				System.out.println("Select a data file to encrypt.");
				dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
				dialog.setVisible(true);
				selected = dialog.getFile();
				if (selected != null) {
					try {
						M = Files.readAllBytes(Paths.get(dialog.getDirectory() + selected));
						
						System.out.println("Select a elliptic public key file.");
						dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
						dialog.setVisible(true);
						selected = dialog.getFile();
						if (selected != null) {
							EllipticCurvePoint publicKey = EllipticCurvePoint.readKeyFromFile(selected);
							EllipticCurveCryptogram.writeCryptogramToFile((EllipticCurve.encryptWithPublicKey(M, publicKey)));
							
							System.out.println("Encrytped data under the public key file is saved as "
												+ "ENCRYPTED_CRYPTOGRAM in the local source file.");
						} else {
							System.out.println("User did not select a file.");
						}
					} catch(Exception e) {
						e.printStackTrace();
					}
				} else {
					System.out.println("User did not select a file.");
				}
				break;
				
				
			// [PART 4] Decrypt a given elliptic-encrypted file from a given password
			case 8:
				System.out.println("Select a file");
				dialog = new FileDialog(new JFrame(), "Select a file", FileDialog.LOAD);
				dialog.setVisible(true);
				selected = dialog.getFile();
				if (selected != null) {
					EllipticCurveCryptogram cryptogram = (EllipticCurveCryptogram)HASH.readCryptogramFromFile(Paths.get(dialog.getDirectory() + selected).toString());
					hashFunction = new HASH();
					myScanner = new Scanner(System.in);
					System.out.println("Enter a passphrase: ");
					String pw1 = myScanner.nextLine();
					msg = EllipticCurve.decryptWithPW(cryptogram, pw1.getBytes());
					
					System.out.println("DECRYPTED MESSAGE HAS BEEN SAVED TO OUTPUT_ELLIPTIC_FILE.TXT");
					
					// write to new output file of decrypted message
					File output = new File("output_elliptic_file.txt");
					Path path = Paths.get(output.getName());
					try {
						Files.write(path, msg);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				} else {
					System.out.println("User did not select a file.");
				}
				break;
				
				
			// [PART 5] Sign a give file from a given password and write the signature to a file
			case 9:
				break;
			
			// [PART 5] Verify a given data file and its signature file under a given public key file
			case 10:
				break;
			
			default:
				System.out.println("Not a valid selection.");
				
			}
			System.out.println();
			System.out.println("Make another selection or choose to exit the program.");
			printMainMenu();	// Let user select another service
			userSelection();
		}
	}

}
