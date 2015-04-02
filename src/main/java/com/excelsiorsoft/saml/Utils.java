/**
 * 
 */
package com.excelsiorsoft.saml;

import java.io.FileInputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.util.Base64;

/**
 * @author sleyzerzon
 *
 */
public final class Utils {
	
    @SuppressWarnings ({ "unchecked", "rawtypes" })
    public final static <T> T create (Class<T> cls, QName qname)
    {
        return (T) ((XMLObjectBuilder) 
            Configuration.getBuilderFactory ().getBuilder (qname))
                .buildObject (qname);
    }
    
    
    @SuppressWarnings("rawtypes")
	public final static List<String> getHostAddresses() throws Throwable {
    	
    	List<String> result = new ArrayList<>();
    	
    	Enumeration e = NetworkInterface.getNetworkInterfaces();
    	while(e.hasMoreElements())
    	{
    	    NetworkInterface n = (NetworkInterface) e.nextElement();
    	    Enumeration ee = n.getInetAddresses();
    	    while (ee.hasMoreElements())
    	    {
    	        InetAddress i = (InetAddress) ee.nextElement();
    	        //System.out.println(i.getHostAddress());
    	        if(i instanceof Inet6Address || i.isLoopbackAddress()/*.getHostAddress().contains("127.0.0.1") || i.getHostAddress().contains("0:0:0:0:0")*/) continue;
    	        result.add(i.getHostAddress());
    	    }
    	}
    	
    	return result;
    }
    
    
	/*
	   public final static String obtainEncodedX509Certificate(String publicKeyLocation) throws Throwable{
		
		String result = "foo-value";
		
		FileInputStream fin = new FileInputStream(publicKeyLocation);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		
		result = (Base64.encodeBytes(certificate.getEncoded()));
		//PublicKey pk = certificate.getPublicKey();
		
		
		return result;
	}*/
    
    public static void main(String [] args) throws Throwable{
    	for(Iterator<String> it = getHostAddresses().iterator(); it.hasNext();){
    		System.out.println(it.next());
    		
    	}
    	
    }

}
