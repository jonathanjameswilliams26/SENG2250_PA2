import java.math.BigInteger;

public class RSAPrivateKey {

    private BigInteger d;
    private BigInteger n;

    public RSAPrivateKey(BigInteger d, BigInteger n) {
        this.d = d;
        this.n = n;
    }

    public BigInteger getD(){return d;}
    public BigInteger getN() {return n;}
}