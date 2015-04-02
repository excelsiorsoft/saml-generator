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
	public static final String FIRST_NAME = "FirstName";
	public static final String MIDDLE_NAME = "MiddleName";
	public static final String LAST_NAME = "LastName";
	public static final String SUFFIX_NAME = "SuffixName";
	public static final String STREET_NAME_1 = "StreetName1";
	public static final String STREET_NAME_2 = "StreetName2";
	public static final String CITY_NAME = "CityName";
	public static final String STATE = "State";
	public static final String ZIP_CODE = "ZipCode";
	public static final String SSN = "SSN";
	public static final String DATE_OF_BIRTH = "DateOfBirth";
	public static final String PHONE_NUMBER = "PhoneNumber";
	public static final String PARTNER_ENTITY_ID = "partnerEntityId";
	public static final String SUBJECT_NAME = "subjectName";

	/*public static final String[] govtAttributes = { TRANSACTION_ID,
			STATE_EXCHANGE_CODE, PARTNER_ASSIGNED_CONSUMER_ID,
			FFE_ASSIGNED_CONSUMER_ID, USER_TYPE, FFE_USER_ID, TRANSFER_TYPE,
			RETURN_URL, KEEP_ALIVE_URL, NPN, PLAN_RESULTS_FILTER, FIRST_NAME,
			MIDDLE_NAME, LAST_NAME, SUFFIX_NAME, STREET_NAME_1, STREET_NAME_2,
			CITY_NAME, STATE, ZIP_CODE, SSN, DATE_OF_BIRTH, EMAIL, PHONE_NUMBER };*/

	@SuppressWarnings("serial")
	public static Map<String, String> govtAttributesWithDefaults = new HashMap<String, String>() {

		{
			put(ISSUER, "ffx-ffe-w7-15.cgifederal.com");
			put(TRANSACTION_ID, "2f3f2d3d-00cf-47ed-bb05-fd158e4b4180");
			put(STATE_EXCHANGE_CODE, "MD0");
			put(PARTNER_ASSIGNED_CONSUMER_ID, "1234");
			put(FFE_ASSIGNED_CONSUMER_ID, "6ad66f44-d7f3-4ec1-b832-bb769749ff1c");
			put(USER_TYPE, "Consumer");
			put(FFE_USER_ID, "john.doe@email.com");
			put(TRANSFER_TYPE, "Direct Enrollment");
			put(RETURN_URL, "https://www.bcbs.com/partnersite");
			put(KEEP_ALIVE_URL, "https://www.bcbs.com/extendsession.jsp");
			put(NPN, "");
			put(PLAN_RESULTS_FILTER, "10270,10224");
			put(FIRST_NAME, "JOHN");
			put(MIDDLE_NAME, "FISCHER");
			put(LAST_NAME, "DOE");
			put(SUFFIX_NAME, "");
			put(STREET_NAME_1, "1234 Fishy Ln");
			put(STREET_NAME_2, "SUITE 124");
			put(CITY_NAME, "Peoria");
			put(STATE, "IL");
			put(ZIP_CODE, "20190");
			put(SSN,"123-45-6789");
			put(DATE_OF_BIRTH,"01/01/1951");
			put(EMAIL,"john.doe@email.com");
			put(PHONE_NUMBER,"531-321-2001");
			put(PARTNER_ENTITY_ID,"SamlAssertion-"+"25171a8736ed098dde8659e5ba250b5f");
			put(SUBJECT_NAME, "CN=ffx-ffe-w7-15.cgifederal.com,OU=ffx,OU=ffe,O=cgifederal,L=Herndon,ST=VA,C=US");
			

		}

		;
	};
	
	public static final List<String> exludedAttributes =  Arrays.asList(PARTNER_ENTITY_ID, SUBJECT_NAME);

	public static void main(String[] args) {
		try {

			//String issuer = null;
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
			options.addOption(PUBLIC_KEY, true,
					"Location of public key to decrypt assertion");
			options.addOption(PRIVATE_KEY, true,
					"Location or private key use to sign assertion");
			options.addOption(SAML_ASSERTION_EXPIRATION_DAYS, true,
					"How long before assertion is no longer valid. Can be negative.");

			options.addOption(TRANSACTION_ID, true, "Transaction ID.");
			options.addOption(STATE_EXCHANGE_CODE, true, "State Exchange Code.");
			options.addOption(PARTNER_ASSIGNED_CONSUMER_ID, true,
					"Partner Assigned Consumer ID");
			options.addOption(FFE_ASSIGNED_CONSUMER_ID, true,
					"FFE Assigned Consumer ID");
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

			//issuer = cmd.getOptionValue(ISSUER);
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
					new DateTime(), /* "password", */buildAttributes(cmd),
					/*issuer,*/ samlAssertionExpirationDays);

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

		/*
		 * for (Iterator<?> it = new ArrayIterator(govtAttributes);
		 * it.hasNext();) {
		 * 
		 * @SuppressWarnings("unused") String name = (String) it.next(); String
		 * value = cmd.getOptionValue(name); if (value != null){
		 * attributes.put(DOMAIN, Arrays.asList(value)); }else{
		 * 
		 * } }
		 */

		for (Map.Entry<String, String> entry : govtAttributesWithDefaults
				.entrySet()) {
			String name = entry.getKey();
			String value = entry.getValue();
			if (value != null)
				attributes.put(name, Arrays.asList(value.split(",")));
		}

		/*
		 * String domain = cmd.getOptionValue(DOMAIN); if (domain != null)
		 * attributes.put(DOMAIN, Arrays.asList(domain));
		 * 
		 * String roles = cmd.getOptionValue(ROLES); if (roles != null)
		 * attributes.put(ROLES, Arrays.asList(roles.split(",")));
		 * 
		 * String email = cmd.getOptionValue(EMAIL); if (email != null)
		 * attributes.put(EMAIL, Arrays.asList(email));
		 */

		return attributes;

	}
}
