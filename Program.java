public class Program {
    public static void main(String[] args) {
        
        //Create Alice and Bob clients
        Alice alice = new Alice();
        Bob bob = new Bob();

        //Exchange RSA public keys as the spec says the clients know each others public keys
        System.out.println("Alice and Bob Exchange RSA public keys");
        alice.setOtherPublicKey(bob.getRSAKeys().getPublicKey());
        bob.setOtherPublicKey(alice.getRSAKeys().getPublicKey());

        //Begin the Station to Station Protocol

        //Step 1: Alice sends g^a to bob
        printSectionTitle("STS Protocol Step 1:");
        Message messageToSendToAlice = bob.STS_step1(alice.getDH().getGX());

        //Step 2: Bob sends g^b to Alice along with a encrypted message E(sign[gB,gA])
        //Alice confirms Bob is authenticated by confirming the nonce
        printSectionTitle("STS Protocol Step 2:");
        alice.STS_step2(messageToSendToAlice);

        //Step 3: Alice sends an encrypted message for Bob to verify. Sending E(Sign[gA,gB])
        //Bob confirms Alice is authenticated by confirming the nonce
        printSectionTitle("STS Protocol Step 3:");
        Message messageToSendToBob = alice.STS_step3();
        bob.STS_step3(messageToSendToBob);

        //The STS Protocol is now complete, both Alice and Bob have been authenticated
        printSectionTitle("STS Protocol Complete");
    }

    public static void printSectionTitle(String title) {
        System.out.println("\n**********************************************************************");
        System.out.println(title);
        System.out.println("**********************************************************************");
    }
}