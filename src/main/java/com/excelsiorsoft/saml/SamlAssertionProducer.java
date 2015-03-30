package com.excelsiorsoft.saml;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class SamlAssertionProducer {

	private String privateKeyLocation;
	private String publicKeyLocation;
	private CertManager certManager = new CertManager();

	public Response createSAMLResponse(final String subjectId,
			final DateTime authenticationTime, final String credentialType,
			final HashMap<String, List<String>> attributes, String issuer,
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
		ResponseBuilder responseBuilder = new ResponseBuilder();
		Response response = responseBuilder.buildObject();
		response.setID(UUID.randomUUID().toString());
		response.setIssueInstant(issueDate);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(issuer);
		response.setStatus(status);
		response.getAssertions().add(assertion);
		return response;
	}

	private Assertion createAssertion(final DateTime issueDate,
			Subject subject, Issuer issuer, AuthnStatement authnStatement,
			AttributeStatement attributeStatement) {
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(issueDate);
		assertion.setSubject(subject);
		assertion.setIssuer(issuer);

		if (authnStatement != null)
			assertion.getAuthnStatements().add(authnStatement);

		if (attributeStatement != null)
			assertion.getAttributeStatements().add(attributeStatement);

		return assertion;
	}

	private Issuer createIssuer(final String issuerName, final boolean needFormat) {
		// create Issuer object
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerName);
		if (needFormat) issuer.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
		return issuer;
	}

	private Subject createSubject2(final String subjectId,
			final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);

		// create name element
		//NameIDBuilder nameIdBuilder = new NameIDBuilder();
		NameID nameId = new NameIDBuilder().buildObject();
		nameId.setValue(subjectId);
		//nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
		nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		//SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
		SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
		subjectConfirmationData.setNotOnOrAfter(currentDate);

		//SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
		SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
		//subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");
		//subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		NameID subjConfNameId = new NameIDBuilder().buildObject();
		subjConfNameId.setValue("CN=soapuiks_1, OU=FEPS, O=CGI-Federal, L=Herndon, ST=VA, C=US");
		subjectConfirmation.setNameID(subjConfNameId);

		// create subject element
		//SubjectBuilder subjectBuilder = new SubjectBuilder();
		Subject subject = new SubjectBuilder().buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		return subject;
	}
	
	private Subject createSubject(final String subjectId,
			final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);

		// create name element
		NameID nameId = new NameIDBuilder().buildObject();
		nameId.setValue(subjectId);
		nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

		SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
		subjectConfirmationData.setNotOnOrAfter(currentDate);


		SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");
		NameID subjConfNameId = new NameIDBuilder().buildObject();
		subjConfNameId.setValue("CN=soapuiks_1, OU=FEPS, O=CGI-Federal, L=Herndon, ST=VA, C=US");
		subjectConfirmation.setNameID(subjConfNameId);

		// create subject element
		Subject subject = new SubjectBuilder().buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		return subject;
	}	

	private AuthnStatement createAuthnStatement(final DateTime issueDate) {
		
		// create authcontextclassref object
		//AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef classRef = new AuthnContextClassRefBuilder().buildObject();
		classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		// create authcontext object
		//AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
		AuthnContext authnContext = new AuthnContextBuilder().buildObject();
		authnContext.setAuthnContextClassRef(classRef);

		// create authenticationstatement object
		//AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
		AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
		authnStatement.setAuthnInstant(issueDate);
		authnStatement.setAuthnContext(authnContext);

		return authnStatement;
	}

	private AttributeStatement createAttributeStatement(
			HashMap<String, List<String>> attributes) {
		
		// create authenticationstatement object
		//AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

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
		StatusCode statusCode = new StatusCodeBuilder().buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);

		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);

		return status;
	}

	private Signature createSignature() throws Throwable {
		
		if (publicKeyLocation != null && privateKeyLocation != null) {
			
			//SignatureBuilder builder = new SignatureBuilder();
			Signature signature = new SignatureBuilder().buildObject();
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
