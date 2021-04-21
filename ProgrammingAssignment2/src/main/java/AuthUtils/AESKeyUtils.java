package AuthUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESKeyUtils {
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(new SecureRandom());
        return keygen.generateKey();
    }

    private static Cipher getCipher (int mode, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher desCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        desCipher.init(mode, key);
        return desCipher;
    }

    public static byte[] encrypt_bytes(byte[] bytes, SecretKey key) throws Exception{
        Cipher encryptCipher = getCipher(Cipher.ENCRYPT_MODE, key);
        byte[] encryptBytes = encryptCipher.doFinal(bytes);
        return encryptBytes;

    }

    public static byte[] decrypt_bytes(byte[] bytes, SecretKey key) throws Exception{
        Cipher decryptCipher = getCipher(Cipher.DECRYPT_MODE, key);
        byte[] decryptBytes = decryptCipher.doFinal(bytes);
        return decryptBytes;

    }
}
