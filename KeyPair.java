/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class is the RSA public and private key pair.
 */
public class KeyPair {

    private RSAKey publicKey;   //The RSA public key (e,n)
    private RSAKey privateKey;  //The RSA private key (d,n)


    /**
     * Constructor, setting the public and private key for the pair
     * @param publicKey - The RSA public key
     * @param privateKey - The RSA private key
     */
    public KeyPair(RSAKey publicKey, RSAKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }


    //GETTER
    public RSAKey getPrivateKey() {
        return privateKey;
    }

    //GETTER
    public RSAKey getPublicKey() {
        return publicKey;
    }

    
    @Override
    public String toString() {
        String message = "RSA Public Key: " + publicKey.toString()
                        + "\nRSA Private Key: " + privateKey.toString();
        return message;
    }
}