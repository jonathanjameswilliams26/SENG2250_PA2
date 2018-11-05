import java.math.BigInteger;

public class Alice extends Client {

    private BigInteger gB;

    public Alice() {
        super("Alice");
    }


    public void STS_step2(Message messageReceived) {
        System.out.println("Alice: Received g^b from Bob and an encrypted message.");

        //Calculate the session key from g^b send by Bob
        gB = new BigInteger(messageReceived.getUnsecureMessage());
        calcSessionKey(gB);

        //Decrypt the ciphertext using 3DES with counter mode
        System.out.println("Alice: Decrypting message using 3DES");
        TripleDES decryption = new TripleDES(messageReceived.getCounterUsed());
        byte[] plaintext = decryption.counterMode(messageReceived.getCipertext(), sessionKey);
        System.out.println("Alice: Decryption complete.");

        //Verify the signature

        //The message expected to be received from Bob
        String expectedMessage = gB.toString() + "," + dh.getGX().toString();

        //The correct digest generated from the expected message
        String correctMessageDigest = SHA256.generateDigest(expectedMessage);

        //Decrypt the message using Bobs RSA public key to get the digest he signed
        String signedDigest = RSA.decrypt(plaintext, otherPublicKey);

        //Confirm the digests match
        if(correctMessageDigest.equals(signedDigest))
            System.out.println("Alice: Message sent by Bob has been successfully verified.");
        else
        {
            System.out.println("Alice: The message sent by Bob is incorrect. Terminating program.");
            System.exit(1);
        }
    }


    public Message STS_step3() {

        System.out.println("Alice: Sending encrypted message to Bob. Sending E(Sign[gA,gB])");

        //Create the plaintext to send
        String plaintext = dh.getGX().toString() + "," + gB.toString();

        //Sign the plaintext using Alices RSA private key
        byte[] signedMessage = RSA.encrypt(plaintext, rsaKeys.getPrivateKey());

        //Encrypt the signed message using 3DES with counter mode
        System.out.println("Alice: Encrypting digitally signed message using 3DES with counter mode.");
        TripleDES encryption = new TripleDES();
        byte[] ciphertext = encryption.counterMode(signedMessage, sessionKey);
        System.out.println("Alice: Encryption complete.");

        //Create the message to send to Bob
        Message messageToSendToBob = new Message(ciphertext, encryption.getInitialCounter());

        return messageToSendToBob;
    }
}