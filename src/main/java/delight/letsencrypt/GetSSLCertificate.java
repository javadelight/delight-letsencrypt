package delight.letsencrypt;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.swing.JOptionPane;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.mxro.file.Jre.FilesJre;
import de.mxro.httpserver.HttpService;
import de.mxro.httpserver.netty3.Netty3Server;
import de.mxro.httpserver.netty3.Netty3ServerComponent;
import de.mxro.httpserver.services.Services;
import delight.async.callbacks.SimpleCallback;
import delight.async.jre.Async;
import delight.functional.Success;

/**
 * A simple client test tool.
 * <p>
 * Pass the names of the domains as parameters.
 * <p>
 * Class based on example for acmej client project
 */
public class GetSSLCertificate {
	public static String USER_KEY_FILE_NAME = "user.key";
	public static String DOMAIN_KEY_FILE_NAME = "domain.key";
	public static String DOMAIN_CSR_FILE_NAME = "domain.csr";
	public static String DOMAIN_CHAIN_FILE_NAME = "domain-chain.crt";

	// File name of the User Key Pair
	private File userKeyFile;

	// File name of the Domain Key Pair
	private File domainKeyFile;

	// File name of the CSR
	private File domainCsrFile;

	// File name of the signed certificate
	private File domainChainFile;

	private void setTargetDir(File targetDir) {
		userKeyFile = getFilePath(targetDir, USER_KEY_FILE_NAME);
		domainKeyFile = getFilePath(targetDir, DOMAIN_KEY_FILE_NAME);
		domainCsrFile = getFilePath(targetDir, DOMAIN_CSR_FILE_NAME);
		domainChainFile = getFilePath(targetDir, DOMAIN_CHAIN_FILE_NAME);
	}

	private File getFilePath(File targetDir, String fileName) {
		return new File(FilesJre.create(targetDir.getAbsolutePath()).get(fileName).getPath());
	}

	// Challenge type to be used
	private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP;

	// RSA key size of generated key pairs
	private static final int KEY_SIZE = 2048;

	private static final Logger LOG = LoggerFactory.getLogger(GetSSLCertificate.class);

	private enum ChallengeType {
		HTTP, DNS, TLSSNI
	}

	Netty3ServerComponent server;

	/**
	 * <p>Creates a certificate for the specified domains.
	 *
	 * @param args
	 *            Domains to get a certificate for
	 */
	public static void main(String... args) {
		if (args.length == 0) {
			System.err.println("Usage: GetSSLCertificate <domain>...");
			System.exit(1);
		}

		FilesJre.create(new File("").getAbsolutePath()).assertFolder("output");

		generateCertificate(Arrays.asList(args), new File("output"));
	}
	
	/**
	 * <p>Creates a certificate and Java KeyStore for the specified domains.
	 * 
	 * @param domains
	 * @param targetDir
	 */
	public static void generateCertificate(List<String> domains, File targetDir) {
		LOG.info("Starting up...");

		Security.addProvider(new BouncyCastleProvider());

		try {
			GetSSLCertificate ct = new GetSSLCertificate();
			ct.setTargetDir(targetDir);
			ct.fetchCertificate(domains);
		} catch (Exception ex) {
			LOG.error("Failed to get a certificate for domains " + domains, ex);
		}

		ConvertToKeystore.convert(new File("output"));

		LOG.info("Java keystore generated in "+targetDir.getAbsolutePath()+"/server.jks. Keystore and cerificate password is 'password'");
	}

	/**
	 * Generates a certificate for the given domains. Also takes care for the
	 * registration process.
	 *
	 * @param domains
	 *            Domains to get a common certificate for
	 */
	public void fetchCertificate(Collection<String> domains) throws IOException, AcmeException {
		// Load the user key file. If there is no key file, create a new one.
		// Keep this key pair in a safe place! In a production environment, you will not
		// be
		// able to access your account again if you should lose the key pair.
		KeyPair userKeyPair = loadOrCreateKeyPair(userKeyFile);

		// Create a session for Let's Encrypt.
		// Use "acme://letsencrypt.org/staging" for test server
		Session session = new Session("acme://letsencrypt.org", userKeyPair);

		// Get the Registration to the account.
		// If there is no account yet, create a new one.
		Registration reg = findOrRegisterAccount(session);

		// Separately authorize every requested domain.
		for (String domain : domains) {
			authorize(reg, domain);
		}

		// Load or create a key pair for the domains. This should not be the
		// userKeyPair!
		KeyPair domainKeyPair = loadOrCreateKeyPair(domainKeyFile);

		// Generate a CSR for all of the domains, and sign it with the domain key pair.
		CSRBuilder csrb = new CSRBuilder();
		csrb.addDomains(domains);
		csrb.sign(domainKeyPair);

		// Write the CSR to a file, for later use.
		try (Writer out = new FileWriter(domainCsrFile)) {
			csrb.write(out);
		}

		// Now request a signed certificate.
		Certificate certificate = reg.requestCertificate(csrb.getEncoded());

		LOG.info("Success! The certificate for domains " + domains + " has been generated!");
		LOG.info("Certificate URI: " + certificate.getLocation());

		// Download the leaf certificate and certificate chain.
		X509Certificate cert = certificate.download();
		X509Certificate[] chain = certificate.downloadChain();

		// Write a combined file containing the certificate and chain.
		try (FileWriter fw = new FileWriter(domainChainFile)) {
			CertificateUtils.writeX509CertificateChain(fw, cert, chain);
		}

		// That's all! Configure your web server to use the DOMAIN_KEY_FILE and
		// DOMAIN_CHAIN_FILE for the requested domains.
	}

	/**
	 * Loads a key pair from specified file. If the file does not exist, a new key
	 * pair is generated and saved.
	 *
	 * @return {@link KeyPair}.
	 */
	private KeyPair loadOrCreateKeyPair(File file) throws IOException {
		if (file.exists()) {
			try (FileReader fr = new FileReader(file)) {
				return KeyPairUtils.readKeyPair(fr);
			}
		} else {
			KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
			try (FileWriter fw = new FileWriter(file)) {
				KeyPairUtils.writeKeyPair(domainKeyPair, fw);
			}
			return domainKeyPair;
		}
	}

	/**
	 * Finds your {@link Registration} at the ACME server. It will be found by your
	 * user's public key. If your key is not known to the server yet, a new
	 * registration will be created.
	 * <p>
	 * This is a simple way of finding your {@link Registration}. A better way is to
	 * get the URI of your new registration with {@link Registration#getLocation()}
	 * and store it somewhere. If you need to get access to your account later,
	 * reconnect to it via {@link Registration#bind(Session, URI)} by using the
	 * stored location.
	 *
	 * @param session
	 *            {@link Session} to bind with
	 * @return {@link Registration} connected to your account
	 */
	private Registration findOrRegisterAccount(Session session) throws AcmeException {
		Registration reg;

		try {
			// Try to create a new Registration.
			reg = new RegistrationBuilder().create(session);
			LOG.info("Registered a new user, URI: " + reg.getLocation());

			// This is a new account. Let the user accept the Terms of Service.
			// We won't be able to authorize domains until the ToS is accepted.
			URI agreement = reg.getAgreement();
			LOG.info("Terms of Service: " + agreement);
			acceptAgreement(reg, agreement);

		} catch (AcmeConflictException ex) {
			// The Key Pair is already registered. getLocation() contains the
			// URL of the existing registration's location. Bind it to the session.
			reg = Registration.bind(session, ex.getLocation());
			LOG.info("Account does already exist, URI: " + reg.getLocation(), ex);
		}

		return reg;
	}

	/**
	 * Authorize a domain. It will be associated with your account, so you will be
	 * able to retrieve a signed certificate for the domain later.
	 * <p>
	 * You need separate authorizations for subdomains (e.g. "www" subdomain).
	 * Wildcard certificates are not currently supported.
	 *
	 * @param reg
	 *            {@link Registration} of your account
	 * @param domain
	 *            Name of the domain to authorize
	 */
	private void authorize(Registration reg, String domain) throws AcmeException {
		// Authorize the domain.
		Authorization auth = reg.authorizeDomain(domain);
		LOG.info("Authorization for domain " + domain);

		// Find the desired challenge and prepare it.
		Challenge challenge = null;
		switch (CHALLENGE_TYPE) {
		case HTTP:
			challenge = httpChallenge(auth, domain);
			break;

		case DNS:
			challenge = dnsChallenge(auth, domain);
			break;

		case TLSSNI:
			challenge = tlsSniChallenge(auth, domain);
			break;
		}

		if (challenge == null) {
			throw new AcmeException("No challenge found");
		}

		// If the challenge is already verified, there's no need to execute it again.
		if (challenge.getStatus() == Status.VALID) {
			return;
		}

		// Now trigger the challenge.
		challenge.trigger();

		// Poll for the challenge to complete.
		try {
			int attempts = 10;
			while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
				// Did the authorization fail?
				if (challenge.getStatus() == Status.INVALID) {
					throw new AcmeException("Challenge failed... Giving up.");
				}

				// Wait for a few seconds
				Thread.sleep(3000L);

				// Then update the status
				challenge.update();
			}
		} catch (InterruptedException ex) {
			LOG.error("interrupted", ex);
			Thread.currentThread().interrupt();
		}

		// All reattempts are used up and there is still no valid authorization?
		if (challenge.getStatus() != Status.VALID) {
			throw new AcmeException("Failed to pass the challenge for domain " + domain + ", ... Giving up.");
		}

		Async.waitFor((cb) -> {
			server.stop(new SimpleCallback() {

				@Override
				public void onFailure(Throwable t) {
					cb.onFailure(t);
				}

				@Override
				public void onSuccess() {
					cb.onSuccess(Success.INSTANCE);
				}
			});

		});

	}

	/**
	 * Prepares a HTTP challenge.
	 * <p>
	 * The verification of this challenge expects a file with a certain content to
	 * be reachable at a given path under the domain to be tested.
	 * <p>
	 * This example outputs instructions that need to be executed manually. In a
	 * production environment, you would rather generate this file automatically, or
	 * maybe use a servlet that returns {@link Http01Challenge#getAuthorization()}.
	 *
	 * @param auth
	 *            {@link Authorization} to find the challenge in
	 * @param domain
	 *            Domain name to be authorized
	 * @return {@link Challenge} to verify
	 */
	public Challenge httpChallenge(Authorization auth, String domain) throws AcmeException {
		// Find a single http-01 challenge
		Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
		if (challenge == null) {
			throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
		}

		String challengePath = "/.well-known/acme-challenge/" + challenge.getToken();

		// Output the challenge, wait for acknowledge...
		LOG.info("Please create a file in your web server's base directory.");
		LOG.info("It must be reachable at: http://" + domain + challengePath);
		LOG.info("File name: " + challenge.getToken());
		LOG.info("Content: " + challenge.getAuthorization());
		LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!");
		LOG.info("If you're ready, dismiss the dialog...");

		StringBuilder message = new StringBuilder();
		message.append("Please create a file in your web server's base directory.\n\n");
		message.append("http://").append(domain).append(challengePath).append("\n\n");
		message.append("Content:\n\n");
		message.append(challenge.getAuthorization());

		try {
			HttpService authorizationService = Services.data(challenge.getAuthorization().getBytes("UTF-8"),
					"plain/text");

			server = Async.waitFor((cb) -> {
				Netty3Server.start(authorizationService, 80, cb);
			});

			// acceptChallenge(message.toString());

		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

		return challenge;
	}

	/**
	 * Prepares a DNS challenge.
	 * <p>
	 * The verification of this challenge expects a TXT record with a certain
	 * content.
	 * <p>
	 * This example outputs instructions that need to be executed manually. In a
	 * production environment, you would rather configure your DNS automatically.
	 *
	 * @param auth
	 *            {@link Authorization} to find the challenge in
	 * @param domain
	 *            Domain name to be authorized
	 * @return {@link Challenge} to verify
	 */
	public Challenge dnsChallenge(Authorization auth, String domain) throws AcmeException {
		// Find a single dns-01 challenge
		Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
		if (challenge == null) {
			throw new AcmeException("Found no " + Dns01Challenge.TYPE + " challenge, don't know what to do...");
		}

		// Output the challenge, wait for acknowledge...
		LOG.info("Please create a TXT record:");
		LOG.info("_acme-challenge." + domain + ". IN TXT " + challenge.getDigest());
		LOG.info("If you're ready, dismiss the dialog...");

		StringBuilder message = new StringBuilder();
		message.append("Please create a TXT record:\n\n");
		message.append("_acme-challenge." + domain + ". IN TXT " + challenge.getDigest());
		acceptChallenge(message.toString());

		return challenge;
	}

	/**
	 * Prepares a TLS-SNI challenge.
	 * <p>
	 * The verification of this challenge expects that the web server returns a
	 * special validation certificate.
	 * <p>
	 * This example outputs instructions that need to be executed manually. In a
	 * production environment, you would rather configure your web server
	 * automatically.
	 *
	 * @param auth
	 *            {@link Authorization} to find the challenge in
	 * @param domain
	 *            Domain name to be authorized
	 * @return {@link Challenge} to verify
	 */
	@SuppressWarnings("deprecation") // until tls-sni-02 is supported
	public Challenge tlsSniChallenge(Authorization auth, String domain) throws AcmeException {
		// Find a single tls-sni-01 challenge
		org.shredzone.acme4j.challenge.TlsSni01Challenge challenge = auth
				.findChallenge(org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE);
		if (challenge == null) {
			throw new AcmeException("Found no " + org.shredzone.acme4j.challenge.TlsSni01Challenge.TYPE
					+ " challenge, don't know what to do...");
		}

		// Get the Subject
		String subject = challenge.getSubject();

		// Create a validation key pair
		KeyPair domainKeyPair;
		try (FileWriter fw = new FileWriter("tlssni.key")) {
			domainKeyPair = KeyPairUtils.createKeyPair(2048);
			KeyPairUtils.writeKeyPair(domainKeyPair, fw);
		} catch (IOException ex) {
			throw new AcmeException("Could not write keypair", ex);
		}

		// Create a validation certificate
		try (FileWriter fw = new FileWriter("tlssni.crt")) {
			X509Certificate cert = CertificateUtils.createTlsSniCertificate(domainKeyPair, subject);
			CertificateUtils.writeX509Certificate(cert, fw);
		} catch (IOException ex) {
			throw new AcmeException("Could not write certificate", ex);
		}

		// Output the challenge, wait for acknowledge...
		LOG.info("Please configure your web server.");
		LOG.info("It must return the certificate 'tlssni.crt' on a SNI request to:");
		LOG.info(subject);
		LOG.info("The matching keypair is available at 'tlssni.key'.");
		LOG.info("If you're ready, dismiss the dialog...");

		StringBuilder message = new StringBuilder();
		message.append("Please use 'tlssni.key' and 'tlssni.crt' cert for SNI requests to:\n\n");
		message.append("https://").append(subject).append("\n\n");
		acceptChallenge(message.toString());

		return challenge;
	}

	/**
	 * Presents the instructions for preparing the challenge validation, and waits
	 * for dismissal. If the user cancelled the dialog, an exception is thrown.
	 *
	 * @param message
	 *            Instructions to be shown in the dialog
	 */
	public void acceptChallenge(String message) throws AcmeException {
		int option = JOptionPane.showConfirmDialog(null, message, "Prepare Challenge", JOptionPane.OK_CANCEL_OPTION);
		if (option == JOptionPane.CANCEL_OPTION) {
			throw new AcmeException("User cancelled the challenge");
		}
	}

	/**
	 * Presents the user a link to the Terms of Service, and asks for confirmation.
	 * If the user denies confirmation, an exception is thrown.
	 *
	 * @param reg
	 *            {@link Registration} User's registration
	 * @param agreement
	 *            {@link URI} of the Terms of Service
	 */
	public void acceptAgreement(Registration reg, URI agreement) throws AcmeException {
		// int option = JOptionPane.showConfirmDialog(null,
		// "Do you accept the Terms of Service?\n\n" + agreement,
		// "Accept ToS",
		// JOptionPane.YES_NO_OPTION);
		// if (option == JOptionPane.NO_OPTION) {
		// throw new AcmeException("User did not accept Terms of Service");
		// }

		// Modify the Registration and accept the agreement
		reg.modify().setAgreement(agreement).commit();
		LOG.info("Updated user's ToS");
	}

}
