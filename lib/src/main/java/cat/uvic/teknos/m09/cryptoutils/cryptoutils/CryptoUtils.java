package cat.uvic.teknos.m09.cryptoutils.cryptoutils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

public class CryptoUtils {


    public static String getHash(byte[] message) throws IOException, NoSuchAlgorithmException {
        var fnmessage = "";
        var properties = new Properties();

        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        var hashAlgorithm = properties.getProperty("hash.algorithm");

        boolean salt = Boolean.parseBoolean((String) properties.get("hash.salt"));

        if (salt) {
            var salt1 = getSalt();
            fnmessage = getDigest(message, salt1, hashAlgorithm);


        } else {
            fnmessage = getDigestNoSalt(message, hashAlgorithm);
        }
        return fnmessage;
    }
    private static String getDigestNoSalt(byte[] data, String algorithm) throws NoSuchAlgorithmException {
        var messageDigest = MessageDigest.getInstance(algorithm);

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }
    private static String getDigest(byte[] data, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
        var messageDigest = MessageDigest.getInstance(algorithm);

        messageDigest.update(salt);

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    private static byte[] getSalt() {
        var secureRandom = new SecureRandom();

        var salt = new byte[16];
        secureRandom.nextBytes(salt);

        return salt;
    }
    public static byte[] encrypt(byte[] plainText, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        var iv = new IvParameterSpec(properties.getProperty("hash.iv").getBytes());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), getSalt(), Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);

        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");

        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(plainText);
    }
    public static byte[] decrypt(byte[] cipherText, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        var iv = new IvParameterSpec(properties.getProperty("hash.iv").getBytes());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), getSalt(), Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);

        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");

        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher.doFinal(cipherText);
    }
git
    public static void main(String[] args) {
        byte[] myvar = "Any String you want".getBytes();
        try {
            System.out.println(getHash(myvar));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }


    }
}
