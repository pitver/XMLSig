package ru.vershinin.utils;

/**
 * Copyright 2004-2012 Crypto-Pro. All rights reserved.
 * Этот файл содержит информацию, являющуюся
 * собственностью компании Крипто-Про.
 *
 * Любая часть этого файла не может быть скопирована,
 * исправлена, переведена на другие языки,
 * локализована или модифицирована любым способом,
 * откомпилирована, передана по сети с или на
 * любую компьютерную систему без предварительного
 * заключения соглашения с компанией Крипто-Про.
 */


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringBufferInputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import com.sun.org.apache.xml.internal.security.encryption.Transforms;
import com.sun.org.apache.xml.internal.security.exceptions.XMLSecurityException;
import com.sun.org.apache.xpath.internal.XPathAPI;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.X509Security;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import wss4j.manager.SignatureManager;
import wss4j.utility.SOAPUtility;
import wss4j.utility.SpecUtility;

/*
 * Class provides generating and verifying of signature. For wss4j 1.5.11 only.
 */
public class SOAPXMLSignatureManager_1_6_3 extends SignatureManager {

    private Object[] samData = null;
    private Provider xmlDSigProvider = null;

    public SOAPXMLSignatureManager_1_6_3(String propertyFile, String alias, char[] StorePassword,
                                         char [] keyPassword) throws ClassNotFoundException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException, FileNotFoundException, IOException {

        // Load JCP
        com.sun.org.apache.xml.internal.security.Init.init();
        SpecUtility.initJCP();

        xmlDSigProvider = new ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI();
        // Create objects to sign and verify SOAP XML messages
        setSAMdata(null, StorePassword, alias, keyPassword);
    }

    private void setSAMdata( File keyStore, char[] keyStorePass, String alias, char[] aliasKeyRecoveryPass)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException,
            IOException, UnrecoverableKeyException {

        // Load key store to extract certificate and key
        KeyStore ks = SpecUtility.loadKeyStore(SpecUtility.DEFAULT_STORETYPE, keyStore, keyStorePass);
        samData = new Object[]{(X509Certificate)ks.getCertificate(alias), ks.getKey(alias, aliasKeyRecoveryPass)};
    }

    /**
     * Function signs XML SOAP document. Document has been already signed in getMessage.
     * @param docStr - XML SOAP string.
     * @return signed document.
     */
    public Document signDoc(String docStr) {

        Document signedDoc = null;

        try {
            // Read only signed document
            SOAPEnvelope envelope = SOAPUtility.getSOAPEnvelopeFromString(docStr);
            signedDoc = envelope.getAsDocument();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return signedDoc;

    }

    /**
     * Private function to verify secured SOAP message.
     * @param message - SOAP message to be verified.
     * @param printCert - option to print certificate.
     * @return boolean result.
     * @throws Exception
     */
    private boolean verifySecuredMessage(SOAPMessage message, boolean printCert) throws Exception {

        // Extract some nodes to verify document
        Document doc = message.getSOAPPart().getEnvelope().getOwnerDocument();
        final Element wssecontext = doc.createElementNS(null, "namespaceContext");
        wssecontext.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:"+"wsse".trim(), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        NodeList secnodeList = XPathAPI.selectNodeList(doc.getDocumentElement(), "//wsse:Security");

        Element r = null;
        Element el = null;
        if( secnodeList != null&&secnodeList.getLength()>0 ) {
            String actorAttr = null;
            for( int i = 0; i<secnodeList.getLength(); i++ ) {
                el = (Element) secnodeList.item(i);
                actorAttr = el.getAttributeNS("http://schemas.xmlsoap.org/soap/envelope/", "actor");
                if(actorAttr != null&&actorAttr.equals("http://smev.gosuslugi.ru/actors/smev")) {
                    r = (Element)XPathAPI.selectSingleNode(el, "//wsse:BinarySecurityToken[1]", wssecontext);
                    break;
                }
            }
        }
        if(r == null)
            return false;

        final X509Security x509 = new X509Security(r);
        if(x509 == null)
            return false;

        // Extract certificate
        final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509.getToken()));

        if (cert == null) {
            throw new Exception("Cannot find certificate to verify signature");
        }

        // Printing of certificate if need
        if (printCert) {
            System.out.println(cert);
        }

        // Get signature node
        NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", xmlDSigProvider);
        // Set public key
        DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(cert.getPublicKey()), nl.item(0));
        javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Verify signature
        return signature.validate(valContext);
    }

    /**
     * Function verifies a signature in SOAP XML document.
     * @param signedDoc - verifiable SOAP XML document with signature.
     * @param printCert - option to print certificate.
     * @return object with result.
     * @throws Exception
     */
    public boolean verifyDoc(Document signedDoc, boolean printCert) {

        String docStr = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        InputStream inputStream = new StringBufferInputStream(docStr);
        MessageFactory messageFactory = null;
        SOAPMessage sm = null;
        boolean result = false;

        try {
            // Create SOAP XML message from string (signed document)
            messageFactory = MessageFactory.newInstance();
            sm = messageFactory.createMessage(null, inputStream);
            // Verify signature
            result = verifySecuredMessage(sm, printCert);
        } catch (SOAPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Function creates signed secured message.
     * @param mf - source message.
     * @throws GeneralSecurityException
     * @throws XMLSecurityException
     * @throws SOAPException
     * @throws ParserConfigurationException
     * @throws TransformerException
     * @throws WSSecurityException
     * @throws FileNotFoundException
     * @throws Exception
     */
    private void constructSecuredMessage(SOAPMessage mf) throws GeneralSecurityException,
            XMLSecurityException, SOAPException, ParserConfigurationException, TransformerException,
            WSSecurityException,FileNotFoundException,Exception {

        if (mf == null)
            return;
        // Prepare secured header
        mf.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        mf.getSOAPPart().getEnvelope().addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        mf.getSOAPPart().getEnvelope().addNamespaceDeclaration("ds", "http://www.w3.org/2000/09/xmldsig#");
        mf.getSOAPBody().setAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "wsu:Id","body");

        WSSecHeader header = new WSSecHeader();
        header.setActor("http://smev.gosuslugi.ru/actors/smev");
        header.setMustUnderstand(false);

        Element sec = header.insertSecurityHeader(mf.getSOAPPart());
        Document doc = mf.getSOAPPart().getEnvelope().getOwnerDocument();

        Element token =(Element) sec.appendChild(doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:BinarySecurityToken"));
        token.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        token.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        token.setAttribute("wsu:Id", "CertId");
        header.getSecurityHeader().appendChild(token);

        // Prepare signature provider
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", xmlDSigProvider);

        Reference ref = fac.newReference("#body", fac.newDigestMethod("http://www.w3.org/2001/04/xmldsig-more#gostr3411", null));
        // Make link to signing element
        SignedInfo si = fac.newSignedInfo( fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                        (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", null),
                Collections.singletonList(ref));

        final Object[] obj = samData.clone();
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // Prepare key information to verify signature in future on other side
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509d = kif.newX509Data(Collections.singletonList((X509Certificate) obj[0]));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

        // Create signature and sign by private key
        javax.xml.crypto.dsig.XMLSignature sig = fac.newXMLSignature(si, ki);
        DOMSignContext signContext = new DOMSignContext((Key) obj[1], token);
        sig.sign(signContext);

        // Insert signature node in document
        Element sigE = (Element) XPathAPI.selectSingleNode(signContext.getParent(), "//ds:Signature");
        Node keyE = XPathAPI.selectSingleNode(sigE, "//ds:KeyInfo", sigE);
        token.appendChild(doc.createTextNode(XPathAPI.selectSingleNode(keyE, "//ds:X509Certificate", keyE).getFirstChild().getNodeValue()));
        keyE.removeChild(XPathAPI.selectSingleNode(keyE, "//ds:X509Data", keyE));
        NodeList chl = keyE.getChildNodes();

        for (int i = 0; i < chl.getLength(); i++) {
            keyE.removeChild(chl.item(i));
        }

        Node str = keyE.appendChild(doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:SecurityTokenReference"));
        Element strRef = (Element)str.appendChild(doc.createElementNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "wsse:Reference"));

        strRef.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        strRef.setAttribute("URI", "#CertId");
        header.getSecurityHeader().appendChild(sigE);
    }

    /**
     * Function returns SOAP message (signed).
     */
    public String getMessage() {

        String messageStr = null;

        try {
            // Create simple secured message
            MessageFactory mf = MessageFactory.newInstance();
            SOAPMessage sm = mf.createMessage();

            // Sign it
            constructSecuredMessage(sm);

            // Convert signed document to string for compatibility with basic interface
            Document doc = sm.getSOAPPart().getEnvelope().getOwnerDocument();
            messageStr = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);

        } catch (SOAPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (XMLSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (TransformerException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (WSSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return messageStr;
    }
}
