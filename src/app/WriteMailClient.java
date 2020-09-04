package app;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.api.services.gmail.Gmail;

import signature.Sign;
import support.MailHelper;
import support.MailWritter;
import util.KeysUtils;
import util.XmlUtils;

public class WriteMailClient extends MailClient {
	static {
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}
	private static final String OUT_FILE = "./data/univerzitet.xml";
	

	public static void main(String[] args) {

		try {
			Gmail service = getGmailService();

			System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert body:");
			String body = reader.readLine();
			
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("protectedEmail");
			
			Element element1 = doc.createElement("mail");
			element1.setTextContent(body);
			rootElement.appendChild(element1);
			
			Element element2 = doc.createElement("title");
			element2.setTextContent(subject);
			rootElement.appendChild(element2);
			
			doc.appendChild(rootElement);
			
			Sign.signDocument(doc);
			
			SecretKey secretKey = KeysUtils.generateSessionKey();
			PublicKey publicKey = KeysUtils.getPublicKey("./data/userb.jks", "userb", "userb", "userb");

			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
		
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);
			System.out.println("Kriptovan tajni kljuc: " + encryptedKey);
			
			KeyInfo keyInfo = new KeyInfo(doc);
			keyInfo.addKeyName("Kriptovani tajni kljuc");
			keyInfo.add(encryptedKey);		
		
			EncryptedData encryptedData = xmlCipher.getEncryptedData();
			encryptedData.setKeyInfo(keyInfo);
			
			xmlCipher.doFinal(doc, rootElement, true);

			String encryptedXml = XmlUtils.DocToString(doc);
			System.out.println("Mail posle enkripcije: " + encryptedXml);

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, "Protected Email", encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);
//			saveDocument(doc, OUT_FILE);

		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}public static void saveDocument(Document doc, String fileName) {
		try {
			File outFile = new File(fileName);
			FileOutputStream f = new FileOutputStream(outFile);

			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();

			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(f);

			transformer.transform(source, result);

			f.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
