import java.math.BigInteger;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class is a subclass of Client.java, this is an Alice client during the STS protocol and
 * message exchange. Alice will communicate with bob
 */
public class Alice extends Client {

    private BigInteger gB;  //Bobs public Diffie Hellman value


    /**
     * Constructor
     */
    public Alice() {
        super("Alice");
    }



    /**
     * Alice completes step 2 of the STS protocol.
     * Alice receives a message from Bob g^b, E(sign[g^b,g^a]).
     * Alice computes the session key and decrypts the message and confirms the signed message is correct
     * @param messageReceived - The message received from Bob
     */
    public void STS_step2(Message messageReceived) {
        printHeader();

        System.out.println("Received g^b from Bob and an encrypted message.");

        //Calculate the session key from g^b send by Bob
        gB = new BigInteger(messageReceived.getUnsecureMessage());
        calcSessionKey(gB);

        //Decrypt the ciphertext using 3DES with counter mode
        System.out.println("Decrypting message using 3DES with counter mode");
        TripleDES decryption = new TripleDES(messageReceived.getCounterUsed());
        byte[] plaintext = decryption.counterMode(messageReceived.getCiphertext(), sessionKey);
        System.out.println("Decryption complete.");

        //Verify the signature

        //The message expected to be received from Bob
        String expectedMessage = gB.toString() + "," + dh.getGX().toString();

        //The correct digest generated from the expected message
        String correctMessageDigest = SHA256.generateDigest(expectedMessage);

        //Decrypt the digital signature using Bobs's RSA public key to get the digest he signed
        boolean authenticated = RSA.verify(plaintext, otherPublicKey, correctMessageDigest);

        //Confirm Bob is authenticated, if not exit the application
        if(authenticated)
            System.out.println("SUCCESS: Bob is authenticated.");
        else
        {
            System.out.println("FAILED: Failed to authenticate Bob.");
            System.exit(1);
        }
        printFooter();
    }




    /**
     * Alice completes step 3 of the STS protocol.
     * Alice generates a message to send to Bob to verify.
     * Alice generates a message E(sign[g^a,g^b]) which will be sent to Bob
     * @return - The message to send to Bob = E(sign[g^a,g^b])
     */
    public Message STS_step3() {
        printHeader();

        System.out.println("Sending encrypted message to Bob. Sending E(Sign[gA,gB])");

        //Create the plaintext to send
        String plaintext = dh.getGX().toString() + "," + gB.toString();

        //Create a digital signature using Alices RSA private key
        byte[] signedMessage = RSA.sign(plaintext, rsaKeys.getPrivateKey());

        //Encrypt the digital signature using 3DES with counter mode
        System.out.println("Encrypting digital signature using 3DES with counter mode.");
        TripleDES encryption = new TripleDES();
        byte[] ciphertext = encryption.counterMode(signedMessage, sessionKey);
        System.out.println("Encryption complete.");

        //Create the message to send to Bob
        Message messageToSendToBob = new Message(ciphertext, encryption.getInitialCounter());

        printFooter();
        return messageToSendToBob;
    }
}