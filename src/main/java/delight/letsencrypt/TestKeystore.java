package delight.letsencrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.net.ssl.SSLContext;

import de.mxro.httpserver.HttpService;
import de.mxro.httpserver.netty3.Netty3Server;
import de.mxro.httpserver.netty3.Netty3ServerComponent;
import de.mxro.httpserver.netty3.Netty3ServerConfiguration;
import de.mxro.httpserver.services.Services;
import de.mxro.sslutils.SslKeyStoreData;
import de.mxro.sslutils.SslUtils;
import delight.async.callbacks.ValueCallback;
import mx.gwtutils.Base64Coder;
import one.utils.jre.OneUtilsJre;

public class TestKeystore {

	public static void main(String[] args) throws FileNotFoundException, IOException {
		
		File original = new File("output/server.jks");
		
		char[] data = Base64Coder.encode(OneUtilsJre.toByteArray(new FileInputStream(original)));
		
		final SslKeyStoreData keyStoreData = SslUtils.createBase64KeyStoreData(new String(data), "password");
		
		System.out.println("valid for "+SslUtils.getDaysUntilExpiry(keyStoreData));
		
		
		
	
		
		Netty3ServerConfiguration conf = new Netty3ServerConfiguration() {
			
			@Override
			public HttpService service() {
				return Services.data("hello".getBytes(), "plain/text");
			}
			
			@Override
			public int port() {
				return 14443;
			}
			
			@Override
			public boolean getUseSsl() {
				return true;
			}
			
			@Override
			public SslKeyStoreData getSslKeyStore() {
				
				return keyStoreData;
			}
		};
		Netty3Server.start(conf, new ValueCallback<Netty3ServerComponent>() {
			
			@Override
			public void onFailure(Throwable t) {
				throw new RuntimeException(t);
			}
			
			@Override
			public void onSuccess(Netty3ServerComponent value) {
				System.out.println("Server started!");
			}
		});
		
	}

}
