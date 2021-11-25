import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSACipherTest {

	private static String keyFile = "/cipher-test/key/customkey.key";
	private static String transformation = "RSA";
	private Cipher cipher;
	ByteArrayInputStream bis = null;
	ByteArrayOutputStream cos = null;

	public RSACipherTest() {
	}

	private String encryptAsymmetric(final String plaintext) {
		System.out.println("\nPlain Text:\n"+plaintext);
		String cipherText = null;
		try {
			Security.addProvider(new BouncyCastleProvider());
			cipher = Cipher.getInstance(transformation, "BC");
			cipher.init(Cipher.ENCRYPT_MODE, loadKey(keyFile, false));

			byte[] plaintextBytes = plaintext.getBytes("UTF-8");
			byte[] buf = new byte[117];
			int bufl = -1;
			bis = new ByteArrayInputStream(plaintextBytes);
			cos = new ByteArrayOutputStream();
			while ((bufl = bis.read(buf)) != -1) {
				cos.write(cipher.doFinal(Arrays.copyOf(buf, bufl)));
			}
			cos.flush();

			byte[] cipherBytes = cos.toByteArray();
			System.out.println("\nCipher:\n"+new String(cipherBytes));
			cipherText = Base64.getEncoder().encodeToString(cipherBytes);
			System.out.println("\nEncoded:\n"+cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (bis != null)
					bis.close();

				if (cos != null)
					cos.close();
			} catch (IOException e) {
			}
		}
		return cipherText;
	}

	private String decryptAsymmetric(final String cipherText) {
		String plainText = null;
		try {
			Security.addProvider(new BouncyCastleProvider());
			cipher = Cipher.getInstance(transformation, "BC");
			cipher.init(Cipher.DECRYPT_MODE, loadKey(keyFile, false));
			
			byte[] text = Base64.getDecoder().decode(cipherText);
			System.out.println("\nDecoded:\n"+new String(text));

			byte[] buf = new byte[128];
			int bufl = -1;
			bis = new ByteArrayInputStream(text);
			cos = new ByteArrayOutputStream();
			while ((bufl = bis.read(buf)) != -1) {
				cos.write(cipher.doFinal(Arrays.copyOf(buf, bufl)));
			}
			cos.flush();

			byte[] decrypted = cos.toByteArray();
			plainText = new String(decrypted, "UTF-8");
			System.out.println("\nDecipher:\n"+plainText);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (bis != null)
					bis.close();

				if (cos != null)
					cos.close();
			} catch (IOException e) {
			}
		}
		return plainText;
	}

	private synchronized Key loadKey(String keyFile, Boolean isPrivate) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			KeyFactory factory = KeyFactory.getInstance("RSA", "BC");		
			byte[] keyBytes = Files.readAllBytes(Paths.get(keyFile));
			if(isPrivate) {
				return factory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
			}
			return factory.generatePublic(new X509EncodedKeySpec(keyBytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) throws Exception {
		RSACipherTest cipherTest = new RSACipherTest();
		cipherTest.decryptAsymmetric(cipherTest.encryptAsymmetric("hello cipher go to hell"));
	}

}