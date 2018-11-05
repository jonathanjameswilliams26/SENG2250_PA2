import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
public class RSA {

    /**
     * CLASS DEMO ONLY - DO NOT RUN AS MAIN PROJECT
     */
    public static void main(String[] args) {

        KeyPair pair = generateRSAKeys();
        
        String plaintext = "Hello this is a testing long message.";
        byte[] ciphertext = encrypt(plaintext, pair.getPrivateKey());
        String decryptedText = decrypt(ciphertext, pair.getPublicKey());
    }



    public static KeyPair generateRSAKeys() {

        //The variables used to calculate the RSA keys
        BigInteger p, q, n, totientN, e, d;
        int bitLength = 512;
        SecureRandom rnd = new SecureRandom();
        boolean complete = false;

        //The KeyPair of public key and private key which will be returned
        KeyPair rsaKeys = null;

        while(!complete)
        {
            //Calculate P and Q
            p = BigInteger.probablePrime(bitLength, rnd);
    		q = BigInteger.probablePrime(bitLength, rnd);
            
            //Confirm P and Q are not equal
            while(p.equals(q))
                q = BigInteger.probablePrime(bitLength, rnd);

            //Calculate N
            n = p.multiply(q);

            //Confirm the key size is 1024 bits
    		if(n.bitLength() != 1024)
                continue;

    		//Calculate the totient of N
    		BigInteger pMinusOne = p.subtract(BigInteger.ONE);
			BigInteger qMinusOne = q.subtract(BigInteger.ONE);
            totientN = pMinusOne.multiply(qMinusOne);
            
            //Set E to the common modulus used in RSA
            e = BigInteger.valueOf(65537);
            
            //Confrim the GCD is 1
            if(!e.gcd(totientN).equals(BigInteger.ONE))
                continue;

            //Calculate D
            d = e.modInverse(totientN);

            //Create the public and private keys
            RSAKey publicKey = new RSAKey(e, n);
            RSAKey privateKey = new RSAKey(d, n);
            rsaKeys = new KeyPair(publicKey, privateKey);
            complete = true;
        }
        return rsaKeys;
    }


    public static byte[] encrypt(String plaintext, RSAKey key) {

        System.out.println("RSA Encryption: Signing Message");

        //Create a digest of the plaintext
        String digest = SHA256.generateDigest(plaintext);

        //Perform the encryption on the digest
        byte[] digestBytes = digest.getBytes(StandardCharsets.UTF_8);
        BigInteger number = new BigInteger(digestBytes);
        BigInteger result = number.modPow(key.getX(), key.getN());
        return result.toByteArray();
    }


    public static String decrypt(byte[] ciphertext, RSAKey key) {
        System.out.println("RSA Decryption: Verifying Digitial Signature");

        //Decrypt the message
        BigInteger number = new BigInteger(ciphertext);
        BigInteger result = number.modPow(key.getX(), key.getN());
        
        //Confirm the decrypted message back to plaintext and return
        byte[] plaintextBytes = result.toByteArray();
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return plaintext;
    }
}