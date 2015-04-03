package com.excelsiorsoft.saml;

import org.joda.time.DateTime;

public class FfmSsoService {
	
	public String partnerToFFM(FlowType flowType){
		
		FfmSamlResponseBuilder producer = new FfmSamlResponseBuilder(FlowType.valueOf("PartnerToFFM"));
		
		/*String responseStr = producer.createSAMLResponse(
				new DateTime(), buildAttributes(cmd));*/
		
		
		return null;
	}
	
	public String ffmToPartner(){
		return null;
	}

}
