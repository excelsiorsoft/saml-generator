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

	public static void main(String[] args) {
		try {

			String issuer = null;
			String subject = null;
			String privateKey = null;
			String publicKey = null;
			Integer samlAssertionExpirationDays = null;

			Options options = new Options();
			options.addOption("issuer", true, "Issuer for saml assertion");
			options.addOption("subject", true, "Subject of saml assertion");
			options.addOption("email", true,
					"Email associated with the subject");
			options.addOption("domain", true, "Domain attribute");
			options.addOption("roles", true, "Comma separated list of roles");
			options.addOption("publicKey", true,
					"Location of public key to decrypt assertion");
			options.addOption("privateKey", true,
					"Location or private key use to sign assertion");
			options.addOption("samlAssertionExpirationDays", true,
					"How long before assertion is no longer valid. Can be negative.");

			// CommandLineParser parser = new GnuParser();
			CommandLine cmd = new GnuParser().parse(options, args);

			if (args.length == 0) {
				// HelpFormatter formatter = new HelpFormatter();
				new HelpFormatter().printHelp("saml-util-1.0", options, true);
				System.exit(1);
			}

			issuer = cmd.getOptionValue("issuer");
			subject = cmd.getOptionValue("subject");
			privateKey = cmd.getOptionValue("privateKey");
			publicKey = cmd.getOptionValue("publicKey");

			samlAssertionExpirationDays = cmd
					.getOptionValue("samlAssertionExpirationDays") != null ? Integer
					.valueOf(cmd.getOptionValue("samlAssertionExpirationDays"))
					: null;

			SamlAssertionProducer producer = new SamlAssertionProducer();
			producer.setPrivateKeyLocation(privateKey);
			producer.setPublicKeyLocation(publicKey);

			Response responseInitial = producer.createSAMLResponse(subject,
					new DateTime(), "password", buildAttributes(cmd), issuer,
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

		String domain = cmd.getOptionValue("domain");
		if (domain != null)
			attributes.put("domain", Arrays.asList(domain));

		String roles = cmd.getOptionValue("roles");
		if (roles != null)
			attributes.put("roles",
					Arrays.asList(roles.split(",")));

		String email = cmd.getOptionValue("email");
		if (email != null)
			attributes.put("email", Arrays.asList(email));

		return attributes;
	}
}
