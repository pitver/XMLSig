package ru.vershinin.utils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Collections;

public class CryptoProJCPXMLDSig {

    private Certificate certificate;
    private PrivateKey privateKey;

    public CryptoProJCPXMLDSig(Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Document signXmlDocument(Document document) throws Exception {
       // XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        Reference reference = createReference(xmlSignatureFactory);
        SignedInfo signedInfo = createSignedInfo(xmlSignatureFactory, reference);
        KeyInfo keyInfo = createKeyInfo(xmlSignatureFactory, certificate);

        DOMSignContext signContext = new DOMSignContext(privateKey, document.getDocumentElement());
        XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
        xmlSignature.sign(signContext);

        return document;
    }

    public boolean verifyXmlDocument(Document document) throws Exception {
        // Implement XML signature verification logic here
        // You will need to parse the XML document and verify the signature
        // using the public key from the certificate
        return false; // Placeholder return value
    }

    private Reference createReference(XMLSignatureFactory factory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        DigestMethod digestMethod = factory.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256", null);
        return factory.newReference("", digestMethod);
    }

    private SignedInfo createSignedInfo(XMLSignatureFactory factory, Reference reference) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
        return factory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));
    }

    private KeyInfo createKeyInfo(XMLSignatureFactory factory, Certificate certificate) throws KeyException {
        KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
        return keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
    }
}

