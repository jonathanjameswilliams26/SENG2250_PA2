import java.math.BigInteger;

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