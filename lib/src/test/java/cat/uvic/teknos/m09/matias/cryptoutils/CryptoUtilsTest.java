package cat.uvic.teknos.m09.matias.cryptoutils;

import cat.uvic.teknos.m09.matias.cryptoutils.exceptions.CryptoUtilsExceptions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilsTest {

    @Test
    void getHash()  {
        byte[] myvar = "Any String you want".getBytes();
        assertTrue(CryptoUtils.getHash(myvar)!="");
    }
    @Test
    void encrypt() {
        byte[] myvar = "Any String you want".getBytes();
        assertNotNull(CryptoUtils.encrypt(myvar,"1234"));

    }

    @Test
    void decrypt(){
        byte[] myvar = "Any String you want".getBytes();
        byte [] encrypted = CryptoUtils.encrypt(myvar,"1234");
        assertNotNull(CryptoUtils.decrypt(encrypted,"1234"));

    }

    @Test
    void sign()  {
        byte[] message = new byte[0];
        try {
            message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("File not found", e);
        }
        assertNotNull(CryptoUtils.sign(message));
    }

    @Test
    void verify(){

        Properties properties = new Properties();
        try {
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("File not found", e);
        }
        byte[] message = new byte[0];
        try {
            message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("File not found", e);
        }
        byte[] certificate = new byte[0];
        try {
            certificate = Files.readAllBytes(Paths.get("src/main/resources/certificate.cer"));
        } catch (IOException e) {
            throw new CryptoUtilsExceptions("File not found", e);
        }

        assertTrue(CryptoUtils.verify(message,CryptoUtils.sign(message),certificate));
    }
}