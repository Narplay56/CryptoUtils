package cat.uvic.teknos.m09.cryptoutils.cryptoutils;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

public class CryptoUtils {

    public static String getHash(byte[] message) throws IOException, NoSuchAlgorithmException {
        var fnmessage = "";

        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("message"));

        var hashAlgorithm = properties.getProperty("hash.algorithm");

        Boolean salt = (Boolean) properties.get("hash.salt");

        if (salt) {
            var salt1 = getSalt();
            fnmessage = getDigest(message, salt1);


        } else {
            fnmessage = getDigestNoSalt(message, hashAlgorithm);
        }
        return fnmessage;
    }
    public static String getDigestNoSalt(byte[] data, String algo) throws NoSuchAlgorithmException {
        var messageDigest = MessageDigest.getInstance(algo);

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }
    public static String getDigest(byte[] data, byte[] salt) throws NoSuchAlgorithmException {
        var messageDigest = MessageDigest.getInstance("SHA-256");

        messageDigest.update(salt);

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    public static byte[] getSalt() {
        var secureRandom = new SecureRandom();

        var salt = new byte[16];
        secureRandom.nextBytes(salt);

        return salt;
    }

}
