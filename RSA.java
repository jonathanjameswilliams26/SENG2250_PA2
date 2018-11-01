public class RSA {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    /**
     * Create a RSA object and generate a public and private key pair
     */
    public RSA() {
        //TODO: generate a public and private key pair
    }


    /**
     * Encrypt the message acting as a digital signature
     * @param message - The message to encypt/sign
     */
    public void encrypt(String message) {
        //TODO: Implement Sign message
    }


    /**
     * Decrypt the message to verify the digital signature.
     * @param message - the message to decrypt
     */ 
    public void decrypt(String message) {
        //TODO: Implement decrypt
    }
}