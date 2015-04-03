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


public class ResponseBuilderConfigurer {

	public static final String SAML_ASSERTION_EXPIRATION_DAYS = "samlAssertionExpirationDays";
	public static final String PRIVATE_KEY = "privateKey";
	public static final String PUBLIC_KEY = "publicKey";
	private static final String ROLES = "roles";
	private static final String DOMAIN = "domain";
	public static final String ISSUER = "issuer";
	public static final String EXCHANGE_ID = "subject";
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
	public static final String PARTNER_ID = "partnerId";
	public static final String FFE_ID = "FFEId";
	public static final String SUBJECT_CONFIRMATION_NAME = "subjectConfirmationName";
	public static final String FLOW_TYPE = "flowType";



	@SuppressWarnings("serial")
	public static Map<String, String> govtAttributesWithDefaults = new HashMap<String, String>() {

		{

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
			put(PARTNER_ID,"ffx-ffe-w7-15.cgifederal.com");
			put(FFE_ID,"ffx-ffe-w7-15.cgifederal.com");
			put(EXCHANGE_ID, "test"); 
			put(SUBJECT_CONFIRMATION_NAME, "CN=ffx-ffe-w7-15.cgifederal.com,OU=ffx,OU=ffe,O=cgifederal,L=Herndon,ST=VA,C=US");
			put(DOMAIN, "");
			put(ROLES,"");
			put(SAML_ASSERTION_EXPIRATION_DAYS,"5");

		}
		
	};
	
	public static final Map<String, String > deploymentSettings = new HashMap<>();
	
	public static final List<String> exludedAttributes =  Arrays.asList(PARTNER_ID, FFE_ID, SUBJECT_CONFIRMATION_NAME, EXCHANGE_ID, DOMAIN, ROLES, SAML_ASSERTION_EXPIRATION_DAYS);

	public final Map<String, List<String>> context;
	
	public static void main(String[] args) {
		try {

			String privateKey = null;
			String publicKey = null;

			Options options = new Options();

			options.addOption(PUBLIC_KEY, true,
					"Location of public key to decrypt assertion");
			options.addOption(PRIVATE_KEY, true,
					"Location or private key use to sign assertion");

			
			options.addOption(FLOW_TYPE, true, "Type of interaction flow.");

			CommandLine cmd = new GnuParser().parse(options, args);

			if (args.length == 0) {
				new HelpFormatter().printHelp("saml-util-1.0", options, true);
				System.exit(1);
			}

			privateKey = cmd.getOptionValue(PRIVATE_KEY);
			publicKey = cmd.getOptionValue(PUBLIC_KEY);
			
			deploymentSettings.put(PRIVATE_KEY, privateKey);
			deploymentSettings.put(PUBLIC_KEY, publicKey);


			FfmSamlResponseBuilder producer = new FfmSamlResponseBuilder(FlowType.valueOf(cmd.getOptionValue(FLOW_TYPE)));
			//producer.setFlowType(FlowType.valueOf(cmd.getOptionValue(FLOW_TYPE))/*PartnerToFFM*/);
			//producer.setPrivateKeyLocation(privateKey);
			//producer.setPublicKeyLocation(publicKey);

			/*Response responseInitial = producer.createSAMLResponse(
					new DateTime(), buildAttributes(cmd));*/
			
			/*String responseStr = producer.createSAMLResponse(
					new DateTime());*/

			/*ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(responseInitial);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);
			String responseStr = new String(baos.toByteArray());*/

			//System.out.println(responseStr);

		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

	public static Map<String, List<String>> buildAttributes(/*CommandLine cmd*/) {

		Map<String, List<String>> attributes = new HashMap<String, List<String>>();


		for (Map.Entry<String, String> entry : govtAttributesWithDefaults
				.entrySet()) {
			String name = entry.getKey();
			String value = entry.getValue();
			if (value != null)
				attributes.put(name, Arrays.asList(value.split(",")));
		}


		return attributes;

	}
	
	public ResponseBuilderConfigurer(){
		this.context = buildAttributes();
	}
}
