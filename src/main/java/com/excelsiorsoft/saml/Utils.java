/**
 * 
 */
package com.excelsiorsoft.saml;

import javax.xml.namespace.QName;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;

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

}
