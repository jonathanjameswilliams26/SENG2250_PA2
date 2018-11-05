import java.math.BigInteger;

public class Bob extends Client {

    private BigInteger gA;

    public Bob() {
        super("Bob");
    }


    public Message STS_step1(BigInteger gA) {

        System.out.println("Bob: Received g^a from Alice");
        this.gA = gA;

        //Calculate the session key using Alice's g^a
        calcSessionKey(gA);

        //Creating the plaintext message as "<Bobs g^b value>,<Alices g^a value>" as described in the lecture slides
		String plaintext =  dh.getGX().toString() + "," + gA.toString();
        
        //Create a digest of the message and sign the message using RSA
        byte[] signedMessage = RSA.encrypt(plaintext, rsaKeys.getPrivateKey());

        //Encrypt the message using 3DES with counter mode
        System.out.println("Bob: Encrypting digitally signed message using 3DES with counter mode.");
        TripleDES encryption = new TripleDES();
        byte[] ciphertext = encryption.counterMode(signedMessage, sessionKey);
        System.out.println("Bob: Encryption complete.");

        //Create the message to send to Alice
        System.out.println("Bob: Sending message to Alice. Sending g^b and an encrypted message. Sending E(sign[g^b,g^a]");
        Message messageToSend = new Message(ciphertext, dh.getGX().toString(), encryption.getInitialCounter());
        return messageToSend;
    }


    public void STS_step3(Message messageReceived) {
        System.out.println("Bob: Received encrypted message from Alice");

        //The expected message to receive from Alice at this step in the protocol is <g^a,g^b>
        String expectedMessage = gA.toString() + "," + dh.getGX().toString();

        //Create the correct message digest to compare against the signed message
        String correctMessageDigest = SHA256.generateDigest(expectedMessage);

        //Decrypt the ciphertext using 3DES with counter mode
        System.out.println("Bob: Decrypting message using 3DES");
        TripleDES decryption = new TripleDES(messageReceived.getCounterUsed());
        byte[] plaintext = decryption.counterMode(messageReceived.getCipertext(), sessionKey);
        System.out.println("Bob: Decryption complete.");

        //Decrypt the message using Alice's RSA public key to get the digest she signed
        String signedDigest = RSA.decrypt(plaintext, otherPublicKey);

        //Confirm the digests match
        if(correctMessageDigest.equals(signedDigest))
            System.out.println("Bob: Message sent by Alice has been successfully verified.");
        else
        {
            System.out.println("Bob: The message sent by Alice is incorrect. Terminating program.");
            System.exit(1);
        }
    }
}