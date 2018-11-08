import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class represents the 3DES encryption with counter mode.
 * Used to encrypt and decrypt messages.
 */
public class TripleDES {


	//The initial counter used when encrypting a message.
	//Will be sent to the receiver so they can use the same inital counter to decrypt the message
	private byte[] initialCounter; 
	


	/**
	 * Create the 3DES class with a random 64bit counter.
	 */
    public TripleDES() {
		
		//Create a 64 bit counter to be used for the 3DES encryption
		SecureRandom random = new SecureRandom();
		byte one = (byte) random.nextInt(128);
		byte two = (byte) random.nextInt(128);
		byte three = (byte) random.nextInt(128);
		byte four = (byte) random.nextInt(128);
		byte five = (byte) random.nextInt(128);
		byte six = (byte) random.nextInt(128);
		byte seven = (byte) random.nextInt(128);
		byte eight = (byte) random.nextInt(128);
		
		//Create the 64bit counter which was randomly initalised
		initialCounter = new byte[] {one, two, three, four, five, six, seven, eight};
	}
	
	
	/**
	 * Create the 3DES class with the specified initial counter
	 * @param initialCounter
	 */
	public TripleDES(byte[] initialCounter) {
		this.initialCounter = initialCounter;
    }
	
	
	//GETTER
    public byte[] getInitialCounter() {
		return initialCounter;
    }
    



	/**
	 * The 3DES with counter mode. Used for both encryption and decryption.
	 * @param message - The message to encrypt of decrypt
	 * @param sessionKey - The session key used to encrypt or decrypt the message
	 * @return - The byte array of the encrypted or decrypted message
	 */
    public byte[] counterMode(byte[] message, String sessionKey) {
		
		//Create a 24 byte array from the session key which will act as the DES encryption key
		byte[] sessionKeyBytes = sessionKey.getBytes(StandardCharsets.UTF_8);
		byte[] desKeyBytes = Arrays.copyOfRange(sessionKeyBytes, 0, 24);
		byte[] ciphertext = new byte[message.length];
		byte[] counter = Arrays.copyOf(initialCounter, initialCounter.length);
		
		//Create the 3DES secret key from the bytes
		final SecretKey key = new SecretKeySpec(desKeyBytes, "DESede");
		
		try 
		{
			//Setup the 3DES cipher
			final Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			
			//Initialise the index variables
			int messageBytesIndex = 0;
			int ciphertextBytesIndex = 0;
			
			while(messageBytesIndex < message.length)
			{
				//Determine how many bytes are left in the message
				int blockSize = message.length - messageBytesIndex;
				byte[] messageBlock = null;
				
				//If the block size is less than 8 we are at the end of the message, create the smaller size
				if(blockSize < 8)
					messageBlock = new byte[blockSize];
				else
					messageBlock = new byte[8];
				
				//Fill the message block with the bytes
				for(int i = 0; i < messageBlock.length; i++, messageBytesIndex++)
					messageBlock[i] = message[messageBytesIndex];
				
				//Encrypt the counter using 3DES
				byte[] encryptedCounter = cipher.doFinal(counter);
				
				//Perform the XOR with the counter and the plaintext
				byte[] xor = new byte[messageBlock.length];
				for(int i = 0; i < messageBlock.length; i++)
				{
					int one = (int)messageBlock[i];
					int two = (int)encryptedCounter[i];
					int result = one ^ two;
					xor[i] = (byte)(0xff & result);
				}
				
				//Append the XORed bytes to the ciphertext byte array
				for(int i = 0; i < xor.length; i++, ciphertextBytesIndex++)
					ciphertext[ciphertextBytesIndex] = xor[i];
				
				//Increment counter
				counter = incrementCounter(counter);
			}
			
			//Return the ciphertext
			return ciphertext;
		} 
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
    }
    


	/**
	 * Increments the counter used for encryption or decryption.
	 * Checks the last index of the counter and if the byte is not
	 * at the maximum value it is increased. Otherwise, the previous
	 * index is checked and increased, otherwise it finds the next index to increase.
	 * @param counter - The counter which is being incremented
	 * @return - The incremented counter
	 */
    private byte[] incrementCounter(byte[] counter) {
		
		boolean complete = false;
		int i = 7;
		while(!complete && i >= 0)
		{
			//If the byte is not at the maximum value increment it
			if(counter[i] != 127)
			{
				counter[i]++;
				complete = true;
			}
			
			//Otherwise, move to the next bit
			else
				i--;
		}
		return counter;
	}
}