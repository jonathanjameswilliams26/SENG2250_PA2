import java.math.BigInteger;

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
}