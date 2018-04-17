package delight.letsencrypt;

import java.io.File;

import org.jose4j.http.Get;

import de.mxro.file.FileItem;
import de.mxro.file.Jre.FilesJre;
import de.mxro.process.Spawn;

public class ConvertToKeystore {
	
	public static void main(String[] args) throws InterruptedException {
		
		convert(new File("output/"));
	}
	
	public static void convert(File dir) {
		String script = "";
		script += "#/bin/bash\n";
		script += "rm server.p12\n";
		script += "rm server.jks\n";
		script += "yes \"\" | openssl pkcs12 -export -in "+GetSSLCertificate.DOMAIN_CHAIN_FILE_NAME+" -inkey "+GetSSLCertificate.DOMAIN_KEY_FILE_NAME+" -out server.p12 -name cert -CAfile "+GetSSLCertificate.DOMAIN_CSR_FILE_NAME+" -caname root -passout pass:password\n";
		script += "keytool -genkey -alias server -keystore server.jks -storepass password -keypass password -dname \"CN=Jane Due, OU=JavaSoft, O=Sun, L=Cupertino, S=California, C=US\"\n";
		script += "keytool -delete -alias server -keystore server.jks -storepass password -keypass password\n";
		script += "keytool -v -importkeystore -srckeystore server.p12 -srcstoretype PKCS12 -destkeystore server.jks -deststoretype JKS -storepass password -keypass password -srcstorepass password\n";
				
		FileItem outputDir = FilesJre.create(dir.getAbsolutePath());
		
		outputDir.assertFile("script.sh").setText(script);
		
		System.out.println(Spawn.sh(dir, "chmod +x script.sh"));
		
		System.out.println(Spawn.sh(dir, "./script.sh"));
		
	}
}
