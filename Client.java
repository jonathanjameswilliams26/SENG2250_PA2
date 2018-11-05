import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Client {
    protected String name;
    protected String sessionKey;
    protected DiffieHellman dh;
    protected KeyPair rsaKeys;
    protected RSAKey otherPublicKey;

    public Client(String name) {
        
        this.name = name;

        //Create the Diffie Hellman Values
        System.out.println(name + ": " + "Generating Diffie Hellman Values");
        dh = new DiffieHellman();

        //Generate RSA public and private key pairs
        System.out.println(name + ": " + "Generating RSA Keys");
        rsaKeys = RSA.generateRSAKeys();
    }


    protected void calcSessionKey(BigInteger gY) {
        System.out.println("Calculating Session Key");
        sessionKey = dh.genSessionKey(gY);
        System.out.println("Session Key: " + sessionKey);
    }


    protected void setOtherPublicKey(RSAKey otherPublicKey) {
        this.otherPublicKey = otherPublicKey;
    }

    protected KeyPair getRSAKeys() {
        return rsaKeys;
    }

    protected DiffieHellman getDH() {
        return dh;
    }

    protected void printHeader() {
        System.out.println(name + ": --------------------------------------------------");
    }

    protected void printFooter() {
        System.out.println("-----------------------------------------------------------\n");
    }


    protected void send(Client sendTo) {

        //Capture user input
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
            System.exit(1);

        //Encrypt the message using 3DES with counter mode
        TripleDES encryption = new TripleDES();
        byte[] ciphertext = encryption.counterMode(message.getBytes(StandardCharsets.UTF_8), sessionKey);

        //Create the message to send to the other client
        Message messageToSend = new Message(ciphertext, encryption.getInitialCounter());

        printFooter();
        sendTo.receive(this, messageToSend);
    }


    protected void receive(Client sentBy, Message messageReceived) {

        printHeader();

        //Decrypt the message using 3DES with counter mode
        TripleDES decryption = new TripleDES(messageReceived.getCounterUsed());
        byte[] plaintextBytes = decryption.counterMode(messageReceived.getCiphertext(), sessionKey);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        //Print the received message
        System.out.println("Message Received: " + plaintext);

        //Send a message to the sentBy
        send(sentBy);
    }
}