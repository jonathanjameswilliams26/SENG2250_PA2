/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class represents a message sent between two clients.
 */
public class Message {

    private byte[] ciphertext;          //The encrypted ciphertext
	private String unsecureMessage;     //An unsecure unencrypted message (Optional)
    private byte[] counterUsed;         //The intial counter used when encrypting the message using 3DES counter mode
    

    /**
     * Create a message with ciphertext, an unsecure message, and the intial counter used.
     * This message will be used for STS step 2 when Bob sends M = g^b E(sign[g^b,g^a]) 
     * as g^a will be the unsecure message
     * @param ciphertext - The ciphertext to send
     * @param unsecureMessage - The unsecure message to send
     * @param counterUsed - The initial counter used when encrypting the plaintext using 3DES w/counter mode
     */
    public Message(byte[] ciphertext, String unsecureMessage, byte[] counterUsed) {
        this.ciphertext = ciphertext;
		this.unsecureMessage = unsecureMessage;
		this.counterUsed = counterUsed;
    }



    /**
     * Create a message with ciphertext and counter only.
     * @param ciphertext - The ciphertext to send
     * @param counterUsed - The initial counter used when encrypting the plaintext using 3DES w/counter mode
     */
    public Message(byte[] ciphertext, byte[] counterUsed) {
        this.ciphertext = ciphertext;
		this.unsecureMessage = null;
		this.counterUsed = counterUsed;
    }


    //GETTERS
    public byte[] getCounterUsed() {
		return counterUsed;
	}
	public byte[] getCiphertext() {
		return ciphertext;
    }
    public String getUnsecureMessage() {
        return unsecureMessage;
    }
}