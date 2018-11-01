import java.math.BigInteger;

public class RSAPublicKey {

    private BigInteger e;
    private BigInteger n;

    public RSAPublicKey(BigInteger e, BigInteger n) {
        this.e = e;
        this.n = n;
    }

    public BigInteger getE(){return e;}
    public BigInteger getN() {return n;}
}