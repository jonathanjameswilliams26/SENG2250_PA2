import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
public class RSA {

    
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