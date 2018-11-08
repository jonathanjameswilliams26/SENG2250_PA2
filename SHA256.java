import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * @author Jonathan Williams - 3237808
 * SENG2250 - PA 3
 * 
 * Class Description:
 * This class exposes a SHA256 hash function used to generate message digests.
 */
public class SHA256 {


    /**
     * Generate a message digest of the message passed in.
     * @param message - The message which will be passed into a hash function to generate a hash function.
     * @return - The 256 bit message digest.
     */
    public static String generateDigest(String message) {

        try 
        {
            //Create a digest from the message
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));

            //Convert the digest to a string
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } 
        catch (Exception e) 
        {
            return null;
        }
    }
}