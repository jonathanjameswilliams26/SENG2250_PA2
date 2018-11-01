import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class SHA256 {
    private MessageDigest digest;

    public SHA256() {
        
        try
        {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (Exception e)
        {
            System.out.println("ERROR: An error occurred while trying to obtain SHA-256 algorithm. Exiting Program");
            System.exit(0);
        }
    }


    /**
     * Generates a message digest and returns the string of the generate digest
     * @param message
     * @return
     */
    public String generateDigest(String message) {
        try
        {
            //Get the digest bytes
            byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));

            //Convert the digest to a string
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
        catch (Exception e) 
        {
            return "";
        }
    }



    /**
     * Confirms the message to verify is the same as the digest to compare.
     * Creates a digest of the message to verify and compares the new digest
     * against the digestToCompare
     * @param messageToVerify - The message which is being verified
     * @param digestToCompare - The digest to compare to
     * @return - TRUE = The digests are the same, FALSE otherwise
     */
    public boolean verify(String messageToVerify, String digestToCompare) {
        String newDigest = generateDigest(messageToVerify);
        return newDigest.equals(digestToCompare);
    }
}