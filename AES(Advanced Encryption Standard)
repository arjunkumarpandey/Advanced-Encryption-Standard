import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

public class AES {
    private SecretKey key;
    private static final int KEY_SIZE = 128;
    private static final int T_LEN = 128;
    private Cipher encryptionCipher;

    // This method will create the encryption key
    public void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }

    //Encrypt the plain text data into Cipher text
    public String encrypt(String message) throws Exception {
        byte[] messageBytes = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = encryptionCipher.getIV();
        byte[] encryptedBytes = encryptionCipher.doFinal(messageBytes);
        byte[] combinedIvAndCiphertext = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combinedIvAndCiphertext, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combinedIvAndCiphertext, iv.length, encryptedBytes.length);
        return encode(combinedIvAndCiphertext);
    }
    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    
    
     //Decrypt the Cipher text into 
    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageBytes = decode(encryptedMessage);
        byte[] iv = new byte[12];
        byte[] encryptedBytes = new byte[messageBytes.length - iv.length];
        System.arraycopy(messageBytes, 0, iv, 0, iv.length);
        System.arraycopy(messageBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, iv);
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try {
            AES aes = new AES();
            aes.init();
            String encryptedMessage = aes.encrypt("Hello World");
            String decryptedMessage = aes.decrypt(encryptedMessage);

            System.out.println("Encrypted message: " + encryptedMessage);
            System.out.println("Decrypted message: " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
