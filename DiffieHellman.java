import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class acts as the Diffie Hellman key exchange, storing all values in regards to the 
 * DH key exchange and has the responsibility of calculating the session key.
 */
public class DiffieHellman {

    private static BigInteger p;    //The public prime number
    private static BigInteger g;    //The public generator
    private int x;                  //The clients private value
    private BigInteger gX;          //The clients public value


    /**
     * Constructor, creates a random private value and 
     * generates all required diffie hellman values
     */
    public DiffieHellman() {
        
        //If p and g are null generate them
        if(p == null)
            genP();
        if(g == null)
            genG();

        //Create a random number for the private value
        //Just using a small random number to improve execution time as g^x takes a long time to compute
        //when x is a large number
        SecureRandom rnd = new SecureRandom();
        x = rnd.nextInt(1000);
        gX = g.pow(x);
    }


    //GETTER
    public BigInteger getGX() {
        return gX;
    }


    /**
     * Generates a 256bit session key
     * @param gY - The g^y value of the other client communicating with
     * @return - 256bit session key, calculates g^XY mod p, and hashed the result using SHA256
     */
    public String genSessionKey(BigInteger gY) {

        BigInteger key = gY.modPow(BigInteger.valueOf(x), p);
        return SHA256.generateDigest(key.toString());
    }


    /**
     * Generate the P value for the diffie hellman calculation
     */
    private void genP() {
		int bitLength = 512;
		SecureRandom random = new SecureRandom();
		p = BigInteger.probablePrime(bitLength, random);
    }
    

    /**
     * Generate the G value for the diffie hellman calculation
     */
    private void genG() {
        int bitLength= 512;
        SecureRandom random = new SecureRandom();
        g = BigInteger.probablePrime(bitLength, random);
	}
}