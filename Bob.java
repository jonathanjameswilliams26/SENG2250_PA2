import java.math.BigInteger;

public class Bob extends Client {

    private BigInteger gA;

    public Bob() {
        super("Bob");
    }


    public Message STS_step1(BigInteger gA) {

        printHeader();
        System.out.println("Received g^a from Alice");
        
        //Save the value sent by Alice
        this.gA = gA;

        //Calculate the session key using Alice's g^a
        calcSessionKey(gA);

        //Creating the plaintext message as "<Bobs g^b value>,<Alices g^a value>" as described in the lecture slides
		String plaintext =  dh.getGX().toString() + "," + gA.toString();
        
        //Create a digital signature of the message
        byte[] signedMessage = RSA.sign(plaintext, rsaKeys.getPrivateKey());

        //Encrypt the digital signature using 3DES with counter mode
        System.out.println("Encrypting digital signuature using 3DES with counter mode.");
        TripleDES encryption = new TripleDES();
        byte[] ciphertext = encryption.counterMode(signedMessage, sessionKey);
        System.out.println("Encryption complete.");

        //Create the message to send to Alice
        System.out.println("Sending message to Alice. Sending g^b and an encrypted message. Sending E(sign[g^b,g^a])");
        Message messageToSend = new Message(ciphertext, dh.getGX().toString(), encryption.getInitialCounter());

        printFooter();
        return messageToSend;
    }


    public void STS_step3(Message messageReceived) {
        printHeader();
        System.out.println("Received encrypted message from Alice");

        //The expected message to receive from Alice at this step in the protocol is <g^a,g^b>
        String expectedMessage = gA.toString() + "," + dh.getGX().toString();

        //Create the correct message digest to compare against the digital signature
        String correctMessageDigest = SHA256.generateDigest(expectedMessage);

        //Decrypt the ciphertext using 3DES with counter mode
        System.out.println("Decrypting message using 3DES with counter mode");
        TripleDES decryption = new TripleDES(messageReceived.getCounterUsed());
        byte[] plaintext = decryption.counterMode(messageReceived.getCipertext(), sessionKey);
        System.out.println("Decryption complete.");

        //Decrypt the digital signature using Alice's RSA public key to get the digest she signed
        boolean authenticated = RSA.verify(plaintext, otherPublicKey, correctMessageDigest);

        //Confirm Alice is authenticated, if not exit the application
        if(authenticated)
            System.out.println("SUCCESS: Alice is authenticated.");
        else
        {
            System.out.println("FAILED: Failed to authenticate Alice. Exiting Program");
            System.exit(1);
        }
        printFooter();
    }
}