package com.excelsiorsoft.saml;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import static com.excelsiorsoft.saml.Utils.create;

public class SamlAssertionProducer {

	private String privateKeyLocation;
	private String publicKeyLocation;
	private CertManager certManager = new CertManager();

	public Response createSAMLResponse(final String subjectId,
			final DateTime authenticationTime, final String credentialType,
			final Map<String, List<String>> attributes, String issuer,
			Integer samlAssertionDays) {

		try {
			DefaultBootstrap.bootstrap();

			Signature signature = createSignature();
			Status status = createStatus();
			Issuer responseIssuer = null;
			Issuer assertionIssuer = null;
			Subject subject = null;
			AttributeStatement attributeStatement = null;

			if (issuer != null) {
				responseIssuer = createIssuer(issuer, false);
				assertionIssuer = createIssuer(issuer, true);
			}

			if (subjectId != null) {
				subject = createSubject(subjectId, samlAssertionDays);
			}

			if (attributes != null && attributes.size() != 0) {
				attributeStatement = createAttributeStatement(attributes);
			}

			AuthnStatement authnStatement = createAuthnStatement(authenticationTime);

			Assertion assertion = createAssertion(new DateTime(), subject,
					assertionIssuer, authnStatement, attributeStatement);

			Response response = createResponse(new DateTime(), responseIssuer,
					status, assertion);
			response.setSignature(signature);

			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(response);

			if (response.getSignature() != null) {
				Signer.signObject(signature);
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);

			return response;

		} catch (Throwable t) {
			t.printStackTrace();
			return null;
		}
	}

	public String getPrivateKeyLocation() {
		return privateKeyLocation;
	}

	public void setPrivateKeyLocation(String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	public String getPublicKeyLocation() {
		return publicKeyLocation;
	}

	public void setPublicKeyLocation(String publicKeyLocation) {
		this.publicKeyLocation = publicKeyLocation;
	}

	private Response createResponse(final DateTime issueDate, Issuer issuer,
			Status status, Assertion assertion) {
		
		/*ResponseBuilder responseBuilder = new ResponseBuilder();
		Response response = responseBuilder.buildObject();*/
		
		Response response = create(Response.class,Response.DEFAULT_ELEMENT_NAME);
		response.setID(UUID.randomUUID().toString());
		response.setIssueInstant(issueDate);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(issuer);
		response.setStatus(status);
		response.getAssertions().add(assertion);
		return response;
	}


    private Conditions createConditions(){
    	
    	DateTime now = new DateTime ();
        //assertion.setIssueInstant (now);
	
    Conditions conditions = create 
            (Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore (now.minusSeconds (10));
        conditions.setNotOnOrAfter (now.plusMinutes (30));
        //assertion.setConditions (conditions);
        
        return conditions;
    }
	
	private Assertion createAssertion(final DateTime issueDate,
			Subject subject, Issuer issuer, AuthnStatement authnStatement,
			AttributeStatement attributeStatement) {
		/*AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();*/
		
		Assertion assertion = create(Assertion.class,Assertion.DEFAULT_ELEMENT_NAME);		
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(issueDate);
		assertion.setSubject(subject);
		assertion.setIssuer(issuer);
        assertion.setConditions (createConditions());

        if (attributeStatement != null)
			assertion.getAttributeStatements().add(attributeStatement);
        
		if (authnStatement != null)
			assertion.getAuthnStatements().add(authnStatement);

		return assertion;
	}

	private Issuer createIssuer(final String issuerName, final boolean needFormat) {
		// create Issuer object
/*		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();*/
		Issuer issuer = create(Issuer.class,Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuerName);
		if (needFormat) issuer.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
		return issuer;
	}


	
	private Subject createSubject(final String subjectId,
			final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);

		// create name element
		//NameID nameId = new NameIDBuilder().buildObject();
		NameID nameId = create(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		nameId.setValue(subjectId);
		nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		//SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
		SubjectConfirmationData subjectConfirmationData = create(SubjectConfirmationData.class,SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subjectConfirmationData.setNotOnOrAfter(currentDate);


		//SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
		SubjectConfirmation subjectConfirmation = create(SubjectConfirmation.class, SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");
		//NameID subjConfNameId = new NameIDBuilder().buildObject();
		NameID subjConfNameId = create(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		subjConfNameId.setValue("CN=soapuiks_1, OU=FEPS, O=CGI-Federal, L=Herndon, ST=VA, C=US");
		subjectConfirmation.setNameID(subjConfNameId);

		// create subject element
		//Subject subject = new SubjectBuilder().buildObject();
		Subject subject = create(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		return subject;
	}	

	private AuthnStatement createAuthnStatement(final DateTime issueDate) {
		
		// create authcontextclassref object
		//AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
		//AuthnContextClassRef classRef = new AuthnContextClassRefBuilder().buildObject();
		AuthnContextClassRef classRef = create(AuthnContextClassRef.class, AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		// create authcontext object
		//AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
		AuthnContext authnContext = new AuthnContextBuilder().buildObject();
		authnContext.setAuthnContextClassRef(classRef);

		// create authenticationstatement object
		//AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
		//AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
		AuthnStatement authnStatement = create (AuthnStatement.class,AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnInstant(issueDate);
		authnStatement.setAuthnContext(authnContext);

		return authnStatement;
	}

	private AttributeStatement createAttributeStatement(
			Map<String, List<String>> attributes) {
		
		// create authenticationstatement object
		//AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeStatement attributeStatement = create(AttributeStatement.class, AttributeStatement.DEFAULT_ELEMENT_NAME);
		//AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

		AttributeBuilder attributeBuilder = new AttributeBuilder();
		if (attributes != null) {
			for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
				Attribute attribute = attributeBuilder.buildObject();
				attribute.setName(entry.getKey());

				for (String value : entry.getValue()) {
					XSStringBuilder stringBuilder = new XSStringBuilder();
					XSString attributeValue = stringBuilder.buildObject(
							AttributeValue.DEFAULT_ELEMENT_NAME,
							XSString.TYPE_NAME);
					attributeValue.setValue(value);
					attribute.getAttributeValues().add(attributeValue);
				}

				attributeStatement.getAttributes().add(attribute);
			}
		}

		return attributeStatement;
	}

	private Status createStatus() {
		
		//StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
		//StatusCode statusCode = new StatusCodeBuilder().buildObject();
		StatusCode statusCode = create(StatusCode.class,StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue(StatusCode.SUCCESS_URI);

		//StatusBuilder statusBuilder = new StatusBuilder();
		//Status status = statusBuilder.buildObject();
		Status status = create (Status.class,Status.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(statusCode);

		return status;
	}

	private Signature createSignature() throws Throwable {
		
		if (publicKeyLocation != null && privateKeyLocation != null) {
			
			//SignatureBuilder builder = new SignatureBuilder();
			//Signature signature = new SignatureBuilder().buildObject();
			Signature signature = create(Signature.class,Signature.DEFAULT_ELEMENT_NAME);
			signature.setSigningCredential(certManager.getSigningCredential(
					publicKeyLocation, privateKeyLocation));
			signature
					.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature
					.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			return signature;
		}

		return null;
	}
}
