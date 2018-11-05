public class Message {

    private byte[] ciphertext;
	private String unsecureMessage;
    private byte[] counterUsed;
    
    public Message(byte[] ciphertext, String unsecureMessage, byte[] counterUsed) {
        this.ciphertext = ciphertext;
		this.unsecureMessage = unsecureMessage;
		this.counterUsed = counterUsed;
    }

    public Message(byte[] ciphertext, byte[] counterUsed) {
        this.ciphertext = ciphertext;
		this.unsecureMessage = null;
		this.counterUsed = counterUsed;
    }

    public byte[] getCounterUsed() {
		return counterUsed;
	}
	
	public byte[] getCipertext() {
		return ciphertext;
    }
    
    public String getUnsecureMessage() {
        return unsecureMessage;
    }
}