package ru.vershinin.utils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.xml.transform.OutputKeys.INDENT;

public class XMLDSig {
    String stn="<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"urn://xsd.dmdk.goznak.ru/exchange/3.0\" xmlns:ns1=\"urn://xsd.dmdk.goznak.ru/saleoperation/3.0\">\n" +
            "  <soapenv:Header/>\n" +
            "  <soapenv:Body>\n" +
            "    <ns:SendBatchSaleRequest>\n" +
            "      <ns:CallerSignature>\n" +
            "      </ns:CallerSignature>\n" +
            "      <ns:RequestData id=\"?\">\n" +
            "        <!--1 or more repetitions:-->\n" +
            "        <ns:sale>\n" +
            "          <ns1:index>1</ns1:index>\n" +
            "          <ns1:type>SALE</ns1:type>\n" +
            "          <ns1:cheque>\n" +
            "            <ns1:fn>000</ns1:fn>\n" +
            "            <ns1:fd>CASH_RECEIPT</ns1:fd>\n" +
            "            <ns1:nfd>001</ns1:nfd>\n" +
            "            <ns1:date>2022-02-21</ns1:date>\n" +
            "            <ns1:uinList>\n" +
            "              <ns1:UIN>6432200000902093</ns1:UIN>\n" +
            "            </ns1:uinList>\n" +
            "            <ns1:uinList>\n" +
            "              <ns1:UIN>6432200000902087</ns1:UIN>\n" +
            "            </ns1:uinList>\n" +
            "          </ns1:cheque>\n" +
            "        </ns:sale>\n" +
            "        <ns:sale>\n" +
            "          <ns1:index>2</ns1:index>\n" +
            "          <ns1:type>SALE</ns1:type>\n" +
            "          <ns1:cheque>\n" +
            "            <ns1:fn>000</ns1:fn>\n" +
            "            <ns1:fd>CASH_RECEIPT</ns1:fd>\n" +
            "            <ns1:nfd>002</ns1:nfd>\n" +
            "            <ns1:date>2022-02-21</ns1:date>\n" +
            "            <ns1:uinList>\n" +
            "              <ns1:UIN>6432200000902072</ns1:UIN>\n" +
            "            </ns1:uinList>\n" +
            "          </ns1:cheque>\n" +
            "        </ns:sale>\n" +
            "      </ns:RequestData>\n" +
            "    </ns:SendBatchSaleRequest>\n" +
            "  </soapenv:Body>\n" +
            "</soapenv:Envelope>";
    // Removes "enveloped signature" from a document, so the signature element itself is not digested
    private static final String ENVELOPED_SIGNATURE_TRANSFORM_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    // Canonicals (normalizes) a document. Preserves comments. E.g. removes line feeds, normalizes attributes, CDATA, etc.
    private static final String C14N_CANONICALIZATION_ALGORITHM = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
    private static final String SHA256_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String RSA_SHA512_SIGN_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    private static final C14NMethodParameterSpec EMPTY_C14N_PARAMS = null;
    private static final DigestMethodParameterSpec EMPTY_DIGEST_PARAMS = null;
    private static final SignatureMethodParameterSpec EMPTY_SIGN_PARAMS = null;
    private static final TransformParameterSpec EMPTY_TRANSFORM_PARAMS = null;

    private final Certificate certificate;
    private final PrivateKey privateKey;

    public XMLDSig(Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public static void main(String[] args) {
        try {
            // Загрузите ваш сертификат и закрытый ключ здесь
            Certificate certificate = KeyFactory.getCertificate();
            PrivateKey privateKey = KeyFactory.getPrivateKey();

            XMLDSig xmlDSig = new XMLDSig(certificate, privateKey);

            // Создайте DOM-документ из XML-строки
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(xmlDSig.stn));
            Document document = builder.parse(is);

            // Подпишите документ
            Document signedDocument = xmlDSig.signEnveloped(document);

            System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signedDocument));

            // Выведите подписанный документ в консоль или выполните другие операции
            // ...
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * "Envelops" signature into a document's root element.
     * <pre>
     * {@code
     * <document>
     *     ...
     * </document>
     * }
     * </pre>
     * will become
     * <pre>
     * {@code
     * <document>
     *     ...
     *     <ds:Signature>...</ds:Signature>
     * </document>
     * }
     * </pre>
     */
    public Document signEnveloped(Document document) {
        try {
            XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");

            SignedInfo signedInfo = createSignedInfo(xmlSignatureFactory);
            KeyInfo keyInfo = createKeyInfo(xmlSignatureFactory);
            XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);

            Element callerSignatureElement = (Element) document.getElementsByTagName("ns:CallerSignature").item(0);
            DOMSignContext domSignContext = new DOMSignContext(privateKey, callerSignatureElement);

            xmlSignature.sign(domSignContext);

            return document;
        } catch (MarshalException | InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                XMLSignatureException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static SignedInfo createSignedInfo(XMLSignatureFactory xmlSignatureFactory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        CanonicalizationMethod c14nMethod = xmlSignatureFactory.newCanonicalizationMethod(C14N_CANONICALIZATION_ALGORITHM, EMPTY_C14N_PARAMS);
        DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(SHA256_DIGEST_ALGORITHM, EMPTY_DIGEST_PARAMS);
        SignatureMethod signMethod = xmlSignatureFactory.newSignatureMethod(RSA_SHA512_SIGN_ALGORITHM, EMPTY_SIGN_PARAMS);

        // Before calculating digest (hash) the document is transformed into
        // its canonical (normalized) form so the digest is consistent even
        // if document is reformatted, etc.
        List<Transform> transforms = List.of(
                xmlSignatureFactory.newTransform(ENVELOPED_SIGNATURE_TRANSFORM_ALGORITHM, EMPTY_TRANSFORM_PARAMS),
                xmlSignatureFactory.newTransform(C14N_CANONICALIZATION_ALGORITHM, EMPTY_TRANSFORM_PARAMS)
        );

        // Empty URI points to the root element. Otherwise, the URI would have to point to a signed element.
        Reference referenceDoc = xmlSignatureFactory.newReference("", digestMethod, transforms, null, null);
        List<Reference> references = List.of(referenceDoc);

        return xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);
    }

    private KeyInfo createKeyInfo(XMLSignatureFactory xmlSignatureFactory) {
        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(List.of(certificate));
        return keyInfoFactory.newKeyInfo(List.of(x509Data));
    }

    private DOMSignContext createDomSignContext(Document document) {
        Element rootNode = document.getDocumentElement();
        DOMSignContext domSignContext = new DOMSignContext(privateKey, rootNode);
        // In our example we want to specify XML Signature namespace on the
        // root element of the document. E.g.:
        //
        // <docToSign ... xmlns:ns2="http://www.w3.org/2000/09/xmldsig#">
        //   <ns2:Signature>
        //
        // So, to prefix the signature element with name spaces, we have to
        // specify the namespace via `setDefaultNamespacePrefix()` method.
        //
        // If no default namespace is specified, then the signing algorithm
        // adds namespace to the signature element itself. E.g.:
        //
        // <docToSign ...>
        //   <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        domSignContext.setDefaultNamespacePrefix("ns2");
        return domSignContext;
    }
    public static String toPrettyString(Node node) {
        try {
            Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
            transformer.setOutputProperty(INDENT, "yes");
            transformer.setOutputProperty("{https://xml.apache.org/xslt}indent-amount", "2");

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(node), new StreamResult(outputStream));
            return outputStream.toString(UTF_8);
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
    }



}
