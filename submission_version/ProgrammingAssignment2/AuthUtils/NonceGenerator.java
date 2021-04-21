package AuthUtils;

import java.security.SecureRandom;

public class NonceGenerator {
    public static String get(int length){
        SecureRandom random = new SecureRandom();
        String output = "";
        for(int i = 0; i < length; i++){
            int current_digit = random.nextInt(10);
            output = output + Integer.toString(current_digit);
        }
        return output;
    }
}
