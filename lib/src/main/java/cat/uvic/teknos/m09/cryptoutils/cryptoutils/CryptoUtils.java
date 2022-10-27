package cat.uvic.teknos.m09.cryptoutils.cryptoutils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
    public static byte[] sign (byte[] message) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException {
        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        message = Files.readAllBytes(Paths.get("lib/src/main/resources/message.txt"));
        var keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(properties.getProperty("keystore.name")),
                properties.getProperty("keystore.password").toCharArray());
        var privateKey = keystore.getKey(properties.getProperty("keystore.alias"),
                properties.getProperty("keystore.password").toCharArray());

        var signer = Signature.getInstance(properties.getProperty("keystore.algorithm"));
        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        return signer.sign();

    }

    public static boolean verify (byte[]  message, byte[] signature, byte[] certificate) throws CertificateException, NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        var signer = Signature.getInstance(properties.getProperty("keystore.algorithm"));

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificate);
        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
        try {
            cert.checkValidity();
        } catch( Exception e) {
            System.out.println(e.getMessage());
        }
        var publicKey = cert.getPublicKey();
        signer.initVerify(publicKey);
        signer.update(message);

        return signer.verify(signature);
    }

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
