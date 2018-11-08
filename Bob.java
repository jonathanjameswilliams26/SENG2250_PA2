import java.math.BigInteger;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class is a subclass of Client.java, this is an Bob client during the STS protocol and
 * message exchange. Bob will communicate with Alice
 */
public class Bob extends Client {

    private BigInteger gA; //Alice's public Diffie Hellman value

    /**
     * Constructor
     */
    public Bob() {
        super("Bob");
    }



    /**
     * Bob will complete Step 1 of the STS protocol.
     * Bob receives g^a from Alice and computes the session key.
     * Bob then generates a message to send to Alice, Message = g^b, E(sign[g^b, g^a])
     * @param gA - Alice's public Diffie Hellman value used to generate the session key
     * @return The message g^b, E(sign[g^b, g^a]) which will be sent to Alice
     */
    public Message STS_step1(BigInteger gA) {

        printHeader();
        System.out.println("Received g^a from Alice");
        
        //Save the value sent by Alice
        this.gA = gA;

        //Calculate the session key using Alice's g^a
        calcSessionKey(gA);

        //Creating the plaintext message as "<Bobs g^b value>,<Alices g^a value>" as described in the lecture slides
		String plaintext =  dh.getGX().toString() + "," + gA.toString();
        
        //Create a digital signature of the message using Bobs private RSA key
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




    /**
     * Bob completes step 3 of the STS protocol.
     * Bob receives a encrypted message from Alice E(sign[g^a,g^b]).
     * Bob decrypts the message using the session key and verifies the message sent by Alice
     * to complete the STS protocol.
     * @param messageReceived - the message E(sign[g^a,g^b]) sent by Alice
     */
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
        byte[] plaintext = decryption.counterMode(messageReceived.getCiphertext(), sessionKey);
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