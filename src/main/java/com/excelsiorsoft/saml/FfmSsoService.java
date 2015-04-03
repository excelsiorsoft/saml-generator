package com.excelsiorsoft.saml;

import org.joda.time.DateTime;

public class FfmSsoService {
	
	public String partnerToFFM(String flowType){
		
		FfmSamlResponseBuilder producer = new FfmSamlResponseBuilder(FlowType.valueOf(flowType/*"PartnerToFFM"*/));
		
		String responseStr = producer.createSAMLResponse(new DateTime());
		
		
		return responseStr;
	}
	
	public String ffmToPartner(){
		return null;
	}
	
	public static void main(String[]args){
		
		FfmSsoService cut = new FfmSsoService();
		System.out.println(cut.partnerToFFM("PartnerToFFM"));
	}

}
