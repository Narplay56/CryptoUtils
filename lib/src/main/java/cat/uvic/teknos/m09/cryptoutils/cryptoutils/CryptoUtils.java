package cat.uvic.teknos.m09.cryptoutils.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.cryptoutils.exceptions.CryptoUtilsExceptions;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

public class CryptoUtils {
    private static byte[] hashSalt;

    /**
     *
     * @param message
     * @return
     */
    public static String getHash(byte[] message) {
        var fnmessage = "";
        var properties = new Properties();

        try {
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("No resource found",e);
        }

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

    private static String getDigestNoSalt(byte[] data, String algorithm)  {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }
    private static String getDigest(byte[] data, byte[] salt, String algorithm)  {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

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
    /**
     *
     * @param plainText
     * @param password
     * @return
     */
    public static byte[] encrypt(byte[] plainText, String password){
        var properties = new Properties();
        try {
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("No resource found",e);
        }
        hashSalt = getSalt();
        var iv = new IvParameterSpec(hashSalt);


        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), hashSalt, Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        SecretKey pbeKey = null;
        try {
            pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoUtilsExceptions("Invalid key",e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent", e);
        } catch (NoSuchPaddingException e) {
            throw new CryptoUtilsExceptions("Wrong Padding",e);
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        } catch (InvalidKeyException e) {
            throw new CryptoUtilsExceptions("Invalid key",e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoUtilsExceptions(e);
        }

        try {
            return cipher.doFinal(plainText);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoUtilsExceptions("Illegal block",e);
        } catch (BadPaddingException e) {
            throw new CryptoUtilsExceptions("Bad Padding",e);
        }
    }
    /**
     *
     * @param cipherText
     * @param password
     * @return
     */
    public static byte[] decrypt(byte[] cipherText, String password)  {
        var properties = new Properties();
        try {
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("No resource found",e);

        }
        var base64Encoder = Base64.getEncoder();
        var iv = new IvParameterSpec(hashSalt);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(),hashSalt, Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        SecretKey pbeKey = null;
        try {
            try {
                pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new CryptoUtilsExceptions("Invalid key" ,e);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");

        Cipher cipher = null;
        try {
            try {
                cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));
            } catch (NoSuchPaddingException e) {
                throw new CryptoUtilsExceptions("Wrong Padding",e);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        } catch (InvalidKeyException e) {
            throw new CryptoUtilsExceptions("Invalid key",e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoUtilsExceptions("Invalid algorithm",e);
        }

        try {
            return cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoUtilsExceptions("Illegal block",e);
        } catch (BadPaddingException e) {
            throw new CryptoUtilsExceptions("Bad Padding",e);
        }
    }
    /**
     *
     * @param message
     * @return
     */
    public static byte[] sign (byte[] message) {
        var properties = new Properties();
        try {
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("resource not found",e);
        }
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            throw new CryptoUtilsExceptions("Type error",e);
        }
        try {
            try {
                keystore.load(new FileInputStream(properties.getProperty("keystore.name")),
                        properties.getProperty("keystore.password").toCharArray());
            } catch (IOException e) {
                throw new CryptoUtilsExceptions("Resource not found",e);
            } catch (CertificateException e) {
                throw new CryptoUtilsExceptions("Invalid certificate",e);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }
        Key privateKey = null;
        try {
            try {
                privateKey = keystore.getKey(properties.getProperty("keystore.alias"),
                        properties.getProperty("keystore.password").toCharArray());
            } catch (KeyStoreException e) {
                throw new CryptoUtilsExceptions("Wrong alias",e);
            } catch (UnrecoverableKeyException e) {
                throw new CryptoUtilsExceptions("Wrong password",e);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

        Signature signer = null;
        try {
            signer = Signature.getInstance(properties.getProperty("keystore.algorithm"));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }
        try {
            signer.initSign((PrivateKey) privateKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid private key",e);
        }
        try {
            signer.update(message);
        } catch (SignatureException e) {
            throw new RuntimeException("Signature couldn't update",e);
        }

        try {
            return signer.sign();
        } catch (SignatureException e) {
            throw new RuntimeException("Sign error",e);
        }

    }
    /**
     *
     * @param message
     * @param signature
     * @param certificate
     * @return
     */
    public static boolean verify (byte[]  message, byte[] signature, byte[] certificate) {
        var properties = new Properties();
        try {
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("No resource found",e);
        }

        Signature signer = null;
        try {
            signer = Signature.getInstance(properties.getProperty("keystore.algorithm"));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoUtilsExceptions("Algorithm not existent",e);
        }

        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new CryptoUtilsExceptions("Wrong certificate factory  type",e);
        }
        InputStream in = new ByteArrayInputStream(certificate);
        X509Certificate cert = null;
        try {
            cert = (X509Certificate)certFactory.generateCertificate(in);
        } catch (CertificateException e) {
            throw new CryptoUtilsExceptions("cant generate certificate",e);
        }
        try {
            cert.checkValidity();
        } catch( Exception e) {
            System.out.println(e.getMessage());
        }
        var publicKey = cert.getPublicKey();
        try {
            signer.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            throw new CryptoUtilsExceptions("Invalid key",e);
        }
        try {
            signer.update(message);
        } catch (SignatureException e) {
            throw new CryptoUtilsExceptions("Signature is not valid",e);
        }

        try {
            return signer.verify(signature);
        } catch (SignatureException e) {
            throw new CryptoUtilsExceptions("Invalid signer",e);
        }
    }
}
