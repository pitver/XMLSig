package ru.vershinin.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyFactory {

    private static final KeyStore keyStore = loadKeyStore();

    public static X509Certificate getCertificate() {
        try {
            Certificate certificate = keyStore.getCertificate("test-cert");
            if (certificate instanceof X509Certificate) {
                return (X509Certificate) certificate;
            }
            throw new IllegalArgumentException("X509Certificate not found!");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey() {
        try {
            Key key = keyStore.getKey("test-cert", "123456".toCharArray());
            if (key instanceof PrivateKey ) {
                return (PrivateKey) key;
            }
            throw new IllegalArgumentException("Private key not found!");
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore loadKeyStore() {
        try (InputStream keyStoreStream = KeyFactory.class.getResourceAsStream("/test-keystore.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreStream, "123456".toCharArray());
            return keyStore;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
