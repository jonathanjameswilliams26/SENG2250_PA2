import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class represent a Client for the chat application. This class is a superclass
 * which has 2 subclasses Alice and Bob.
 */
public class Client {
    protected String name;              //The name of the client.
    protected String sessionKey;        //The randomly generated session key
    protected DiffieHellman dh;         //A Diffie Hellman object for performing a key exchange and calculating the session key.
    protected KeyPair rsaKeys;          //This clients RSA private and public key pair
    protected RSAKey otherPublicKey;    //The other client chatting with RSA public key


    /**
     * Constructor
     * @param name - The name of the client
     */
    public Client(String name) {
        
        this.name = name;

        //Create the Diffie Hellman Values
        System.out.println(name + ": " + "Generating Diffie Hellman Values");
        dh = new DiffieHellman();

        //Generate RSA public and private key pairs
        System.out.println(name + ": " + "Generating RSA Keys");
        rsaKeys = RSA.generateRSAKeys();
    }



    /**
     * Calculate the session key using the other client's public Diffie Hellman value
     * @param gY - The other client's public Diffie Hellman value
     */
    protected void calcSessionKey(BigInteger gY) {
        System.out.println("Calculating Session Key");
        sessionKey = dh.genSessionKey(gY);
        System.out.println("Session Key: " + sessionKey);
    }


    //SETTER
    protected void setOtherPublicKey(RSAKey otherPublicKey) {
        this.otherPublicKey = otherPublicKey;
    }

    //GETTER
    protected KeyPair getRSAKeys() {
        return rsaKeys;
    }

    //GETTER
    protected DiffieHellman getDH() {
        return dh;
    }


    //Print statements for formatted console outputs
    protected void printHeader() {
        System.out.println(name + ": --------------------------------------------------");
    }
    protected void printFooter() {
        System.out.println("-----------------------------------------------------------\n");
    }


    /**
     * Send an encrypted message using 3DES encryption 
     * with counter mode message to a specified client.
     * @param sendTo - The client sending the message to
     */
    protected void send(Client sendTo) {

        //Capture user input until the user entered an input
        String message = "";
        Scanner in = new Scanner(System.in);
        while (message.equals(""))
        {
            System.out.println(name + " please enter a message, please type EXIT to exit application: ");
            message = in.nextLine();

            if(message.equals(""))
                System.out.println("Error: You must enter a message:");
        }

        //Exit the application if the user entered EXIT
        if(message.equals("EXIT"))
        {
            in.close();
            System.exit(1);
        }

        //Encrypt the message using 3DES with counter mode
        TripleDES encryption = new TripleDES();
        byte[] ciphertext = encryption.counterMode(message.getBytes(StandardCharsets.UTF_8), sessionKey);

        //Create the message to send to the other client
        Message messageToSend = new Message(ciphertext, encryption.getInitialCounter());

        printFooter();

        //Send the message to the specified client
        sendTo.receive(this, messageToSend);
    }



    /**
     * Receive an encrypted message from a specified client.
     * Decrypt the message and display the results on the screen.
     * @param sentBy - The client who sent the message and how to reply too.
     * @param messageReceived - The message received.
     */
    protected void receive(Client sentBy, Message messageReceived) {

        printHeader();

        //Decrypt the message using 3DES with counter mode
        TripleDES decryption = new TripleDES(messageReceived.getCounterUsed());
        byte[] plaintextBytes = decryption.counterMode(messageReceived.getCiphertext(), sessionKey);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        //Print the received message
        System.out.println("Message Received: " + plaintext);

        //Send a reply message to the sentBy
        send(sentBy);
    }
}