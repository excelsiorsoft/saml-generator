package com.excelsiorsoft.saml;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.collections.iterators.ArrayIterator;
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
	
	public static final String TRANSACTION_ID = "TransactionID";
	public static final String STATE_EXCHANGE_CODE = "StateExchangeCode";
	public static final String PARTNER_ASSIGNED_CONSUMER_ID = "PartnerAssignedConsumerId";
	public static final String FFE_ASSIGNED_CONSUMER_ID = "FFEAssignedConsumerId";
	public static final String USER_TYPE = "UserType";
	public static final String FFE_USER_ID = "FFEUserId";
	public static final String TRANSFER_TYPE = "TransferType";
	public static final String RETURN_URL = "ReturnUrl";
	public static final String KEEP_ALIVE_URL = "KeepAliveUrl";
	public static final String NPN = "NPN";
	public static final String PLAN_RESULTS_FILTER = "PlanResultsFilter";
	public static final String FIRST_NAME ="FirstName";
	public static final String MIDDLE_NAME ="MiddleName";
	public static final String LAST_NAME ="LastName";
	public static final String SUFFIX_NAME ="SuffixName";
	public static final String STREET_NAME_1 ="StreetName1";
	public static final String STREET_NAME_2 ="StreetName2";
	public static final String CITY_NAME ="CityName";
	public static final String STATE ="State";
	public static final String ZIP_CODE ="ZipCode";
	public static final String SSN ="SSN";
	public static final String DATE_OF_BIRTH ="DateOfBirth";
	public static final String PHONE_NUMBER ="PhoneNumber";
	
	public static final String[] govtAttributes = {DOMAIN, ROLES, EMAIL };
	
	

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
			
			options.addOption(TRANSACTION_ID, true,	"Transaction ID.");
			options.addOption(STATE_EXCHANGE_CODE, true, "State Exchange Code.");
			options.addOption(PARTNER_ASSIGNED_CONSUMER_ID, true, "Partner Assigned Consumer ID");
			options.addOption(FFE_ASSIGNED_CONSUMER_ID, true, "FFE Assigned Consumer ID");
			options.addOption(USER_TYPE, true, "User Type");
			options.addOption(FFE_USER_ID, true, "FFE User ID");
			options.addOption(TRANSFER_TYPE, true, "Transfer Type");
			options.addOption(RETURN_URL, true, "Return URL");
			options.addOption(KEEP_ALIVE_URL, true, "Keep Alive URL");
			options.addOption(NPN, true, "NPN");
			options.addOption(PLAN_RESULTS_FILTER, true, "Plan Results Filter");
			options.addOption(FIRST_NAME, true, "First Name");
			options.addOption(MIDDLE_NAME, true, "Middle Name");
			options.addOption(LAST_NAME, true, "Middle Name");
			options.addOption(SUFFIX_NAME, true, "Suffix Name");
			options.addOption(STREET_NAME_1, true, "Street Name 1");
			options.addOption(STREET_NAME_2, true, "Street Name 2");
			options.addOption(CITY_NAME, true, "City Name");
			options.addOption(STATE, true, "State");
			options.addOption(ZIP_CODE, true, "Zip Code");
			options.addOption(SSN, true, "SSN");
			options.addOption(DATE_OF_BIRTH, true, "Date of Birth");
			options.addOption(PHONE_NUMBER, true, "Phone Number");

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
		
		for(Iterator<?> it = new ArrayIterator(govtAttributes);it.hasNext();){
			@SuppressWarnings("unused")
			String name = (String)it.next();
			String value = cmd.getOptionValue(name);
			if (value != null)
				attributes.put(DOMAIN, Arrays.asList(value));
		}

		/*String domain = cmd.getOptionValue(DOMAIN);
		if (domain != null)
			attributes.put(DOMAIN, Arrays.asList(domain));

		String roles = cmd.getOptionValue(ROLES);
		if (roles != null)
			attributes.put(ROLES, Arrays.asList(roles.split(",")));

		String email = cmd.getOptionValue(EMAIL);
		if (email != null)
			attributes.put(EMAIL, Arrays.asList(email));*/

		return attributes;
	}
}
