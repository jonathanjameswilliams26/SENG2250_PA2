public class KeyPair {
    private RSAKey publicKey;
    private RSAKey privateKey;

    public KeyPair(RSAKey publicKey, RSAKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public RSAKey getPrivateKey() {
        return privateKey;
    }

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