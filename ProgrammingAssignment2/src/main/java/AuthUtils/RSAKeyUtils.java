package AuthUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class RSAKeyUtils {
    public static byte[] encrypt_string(String string, Key key) throws Exception{
        Cipher encryptCipher = getCipher(Cipher.ENCRYPT_MODE, key);
        byte[] encryptBytes = encryptCipher.doFinal(string.getBytes());
        return encryptBytes;

    }

    public static String decrypt_string(byte[] bytes, Key key) throws Exception{
        Cipher decryptCipher = getCipher(Cipher.DECRYPT_MODE, key);
        byte[] decryptBytes = decryptCipher.doFinal(bytes);
        return Base64.getEncoder().encodeToString(decryptBytes);

    }

    private static Cipher getCipher (int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(mode, key);
        return desCipher;
    }

}
