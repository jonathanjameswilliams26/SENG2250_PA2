import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class represent an RSA generator which generates RSA public and private key pairs
 * and also performs digital signatures and digital signature verficiation.
 */
public class RSA {


    /**
     * Generate a RSA public and private key pair
     * @return - A RSA public/private key pair
     */
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




    /**
     * Digitally sign a message.
     * Creates a message digest of the plaintext using SHA256
     * and then signs the digest using the RSA key passed in.
     * @param plaintext - The plaintext to sign
     * @param key - The RSA key used to sign the message
     * @return - The digital signature
     */
    public static byte[] sign(String plaintext, RSAKey key) {

        System.out.println("Creating a Digital Signature");

        //Create a digest of the plaintext
        String digest = SHA256.generateDigest(plaintext);

        //Perform the encryption on the digest
        byte[] digestBytes = digest.getBytes(StandardCharsets.UTF_8);
        BigInteger number = new BigInteger(digestBytes);
        BigInteger result = number.modPow(key.getX(), key.getN());
        return result.toByteArray();
    }




    /**
     * Verifies a digital signature.
     * Decrypts the signed message to obtain the message digest
     * and then compares the received digest against the digital signature received.
     * @param ciphertext - The signed ciphertext
     * @param key - The key to verify the digital signature
     * @param digestToCompare - The correct message digest which will be compared agaist the digital signature
     * @return
     */
    public static boolean verify(byte[] ciphertext, RSAKey key, String digestToCompare) {
        System.out.println("Verifying Digitial Signature");

        //Decrypt the message
        BigInteger number = new BigInteger(ciphertext);
        BigInteger result = number.modPow(key.getX(), key.getN());
        
        //Confirm the decrypted message back to plaintext
        byte[] plaintextBytes = result.toByteArray();
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        
        //Compare the decrypted message against the digestToCompare
        boolean isVerified = plaintext.equals(digestToCompare);

        if(isVerified)
            System.out.println("Digital Signature Verification SUCCESSFUL.");
        else
            System.out.println("Digital Signature Verification FAILED.");

        return isVerified;
    }
}