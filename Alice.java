import java.math.BigInteger;

public class Alice extends Client {

    private BigInteger gB;

    public Alice() {
        super("Alice");
    }


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

        //Decrypt the digital signature using Alice's RSA public key to get the digest she signed
        boolean authenticated = RSA.verify(plaintext, otherPublicKey, correctMessageDigest);

        //Confirm Alice is authenticated, if not exit the application
        if(authenticated)
            System.out.println("SUCCESS: Bob is authenticated.");
        else
        {
            System.out.println("FAILED: Failed to authenticate Bob.");
            System.exit(1);
        }
        printFooter();
    }


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