import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class SHA256 {

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