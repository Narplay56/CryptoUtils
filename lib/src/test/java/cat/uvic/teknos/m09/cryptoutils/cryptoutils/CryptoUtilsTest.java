package cat.uvic.teknos.m09.cryptoutils.cryptoutils;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilsTest {

    @Test
    void getHash() throws IOException, NoSuchAlgorithmException {
        byte[] myvar = "Any String you want".getBytes();
        assertTrue(CryptoUtils.getHash(myvar)!="");
    }
    @Test
    void encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        byte[] myvar = "Any String you want".getBytes();
        assertNotNull(CryptoUtils.encrypt(myvar,"1234"));

    }

    @Test
    void decrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        byte[] myvar = "Any String you want".getBytes();
        byte [] encrypted = CryptoUtils.encrypt(myvar,"1234");
        assertNotNull(CryptoUtils.decrypt(encrypted,"1234"));

    }

    @Test
    void sign() throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        var message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));
        assertNotNull(CryptoUtils.sign(message));
    }

    @Test
    void verify() throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, SignatureException, InvalidKeyException {

        Properties properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        var message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));
        var certificate = Files.readAllBytes(Paths.get("src/main/resources/certificate.cer"));

        assertNotNull(CryptoUtils.verify(message,CryptoUtils.sign(message),certificate));
    }
}