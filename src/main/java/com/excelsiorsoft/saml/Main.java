package com.excelsiorsoft.saml;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class Main {

	private static final String SAML_ASSERTION_EXPIRATION_DAYS = "samlAssertionExpirationDays";
	private static final String PRIVATE_KEY = "privateKey";
	private static final String PUBLIC_KEY = "publicKey";
	private static final String ROLES = "roles";
	private static final String DOMAIN = "domain";
	public static final String ISSUER = "issuer";
	public static final String SUBJECT = "subject";
	public static final String EMAIL = "email";

	public static void main(String[] args) {
		try {

			String issuer = null;
			String subject = null;
			String privateKey = null;
			String publicKey = null;
			Integer samlAssertionExpirationDays = null;

			Options options = new Options();
			options.addOption(ISSUER, true, "Issuer for SAML assertion");
			options.addOption(SUBJECT, true, "Subject of SAML assertion");
			options.addOption(EMAIL, true, "Email associated with the subject");
			options.addOption(DOMAIN, true, "Domain attribute");
			options.addOption(ROLES, true, "Comma separated list of roles");
			options.addOption(PUBLIC_KEY, true, "Location of public key to decrypt assertion");
			options.addOption(PRIVATE_KEY, true, "Location or private key use to sign assertion");
			options.addOption(SAML_ASSERTION_EXPIRATION_DAYS, true,
					"How long before assertion is no longer valid. Can be negative.");

			// CommandLineParser parser = new GnuParser();
			CommandLine cmd = new GnuParser().parse(options, args);

			if (args.length == 0) {
				// HelpFormatter formatter = new HelpFormatter();
				new HelpFormatter().printHelp("saml-util-1.0", options, true);
				System.exit(1);
			}

			issuer = cmd.getOptionValue(ISSUER);
			subject = cmd.getOptionValue(SUBJECT);
			privateKey = cmd.getOptionValue(PRIVATE_KEY);
			publicKey = cmd.getOptionValue(PUBLIC_KEY);

			samlAssertionExpirationDays = cmd
					.getOptionValue(SAML_ASSERTION_EXPIRATION_DAYS) != null ? Integer
					.valueOf(cmd.getOptionValue(SAML_ASSERTION_EXPIRATION_DAYS))
					: null;

			SamlAssertionProducer producer = new SamlAssertionProducer();
			producer.setPrivateKeyLocation(privateKey);
			producer.setPublicKeyLocation(publicKey);

			Response responseInitial = producer.createSAMLResponse(subject,
					new DateTime(), /*"password",*/ buildAttributes(cmd), issuer,
					samlAssertionExpirationDays);

			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(responseInitial);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);
			String responseStr = new String(baos.toByteArray());

			System.out.println(responseStr);

		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

	private static Map<String, List<String>> buildAttributes(CommandLine cmd) {

		Map<String, List<String>> attributes = new HashMap<String, List<String>>();

		String domain = cmd.getOptionValue(DOMAIN);
		if (domain != null)
			attributes.put(DOMAIN, Arrays.asList(domain));

		String roles = cmd.getOptionValue(ROLES);
		if (roles != null)
			attributes.put(ROLES, Arrays.asList(roles.split(",")));

		String email = cmd.getOptionValue(EMAIL);
		if (email != null)
			attributes.put(EMAIL, Arrays.asList(email));

		return attributes;
	}
}
