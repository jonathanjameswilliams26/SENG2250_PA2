import java.math.BigInteger;
import java.security.SecureRandom;

public class DiffieHellman {

    private static BigInteger p;
    private static BigInteger g;
    private int x;
    private BigInteger gX;

    /**
     * CLASS DEMO ONLY - DO NOT RUN AS MAIN PROJECT
     */
    public static void main(String[] args) {
        DiffieHellman dh1 = new DiffieHellman();
        DiffieHellman dh2 = new DiffieHellman();

        String sessionKey1 = dh1.genSessionKey(dh2.getGX());
        String sessionKey2 = dh2.genSessionKey(dh1.getGX());

        System.out.println(sessionKey1);
        System.out.println(sessionKey2);
    }


    /**
     * Constructor, creates a random private value and generates all required diffie hellman values
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


    /**
     * Getter
     * @return gX
     */
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