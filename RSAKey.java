import java.math.BigInteger;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class represent an RSA key, containing a value X and value N to compute
 * M^X mod N
 */
public class RSAKey {
    private BigInteger x;
    private BigInteger n;

    public RSAKey(BigInteger x, BigInteger n) {
        this.x = x;
        this.n = n;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getN() {
        return n;
    }

    @Override
    public String toString() {
        return "(" + x + "," + n + ")";
    }
}