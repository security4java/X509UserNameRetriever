/*
 * 	Copyright 2012 Michael Furman
 * 
 * 	Licensed under the Apache License, Version 2.0 (the "License");
 * 	you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  
 *         http://www.apache.org/licenses/LICENSE-2.0
 *         
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  
 */

package org.security4java;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Implementation of <b>X509UserNameRetriever</b> that takes a user name from the Subject Field of the X509Certificate.
 * The user name is the unique part of information from the client certificate that used to identify the identity of the user. 
 * The Subject field (also called Subject Distinguish Name or SubjectDN) identifies the entity associated with the public key.
 * The Subject field contains the following relevant attributes (it can also contain other attributes).
 * 
 * Subject Attribute	Subject Attribute Description		Example
 * CN					Common Name							CN=Bob BobFamily
 * emailAddress			Email Address						emailAddress=bob@example.com
 * C					Country Name						C=US
 * ST					State or Province Name				ST=NY
 * L					Locality Name						L=New York
 * O					Organization Name					O=Work Organization
 * OU					Organizational Unit Name			OU=Managers
 * 
 * To retrieve the user name from the subject, you can use the entire SubjectDN field or the SubjectDN attribute.
 * To retrieve the user name from entire SubjectDN field use the default constructor
 * To retrieve the user name from the SubjectDN attribute, please provide the retrieve attribute name
 * The the retrieve attribute name is a code letter based on a legend defined in the certificate itself.
 * 
 * For example, the Email attribute is used to hold the User Name.
 * Please provide "e" or "emailAddress" for the constructor.
 * 
 * For example, the Common Name attribute is used to hold the User Name.
 * Please provide "CN" for the constructor.
 * 
 *
 */
public class X509SubjectDnRetriever implements X509UserNameRetriever {
	/**
	 * Logger for this class
	 */
	protected final Log log = LogFactory.getLog(getClass());	
	 
	private static final String EMAIL_SUBJECT_ATTR = "emailAddress";

	
	/**
	 * The value is based on a legend defined in the certificate itself.
	 * It tested with the following browsers: IE, FF and Chrome
	 * For new browsers may be will required to add a new legend value to the list.
	 */
	private static final List<String> EmailOptions = Arrays.asList(EMAIL_SUBJECT_ATTR.toLowerCase(), "e") ;

	
	private String subjectDnAttribute = null;
	private String subjectDnAttributeConfiguration = null;
	
	public X509SubjectDnRetriever() {
        setSubjectDnAttribute(null);
    }

	public X509SubjectDnRetriever(String retrieveAttr) {
        setSubjectDnAttribute(retrieveAttr);
    }
    
    /**
     * Set the configuration for X509UserNameRetriever. The X509UserNameRetriever uses the configuration 
     * to retrieve a user name from X509Certificate. 
     * 
     * @param x509UserNameRetrieverConfiguration
     */
    public void setX509UserNameRetrieverConfiguration(String x509UserNameRetrieverConfiguration) { 
    	setSubjectDnAttribute(x509UserNameRetrieverConfiguration);
		
	}
    /* (non-Javadoc)
     * @see org.apache.catalina.realm.X509UserNameRetriever#getUserName(java.security.cert.X509Certificate)
     */
    public String getUserName(X509Certificate clientCert) {
		if (log.isDebugEnabled()) {
			log.debug("getUserName(X509Certificate) - start");
		}
		String subject = getSubjectDN(clientCert);
		String userName = null;
		
		if (subject != null) {
			if (log.isDebugEnabled()) {
				log.debug("Subject is [" + subject + "].");
			}
			if (subjectDnAttribute == null) {
				if (log.isDebugEnabled()) {
					log.debug("subjectDnAttribute is null, so return the whole subject.");
				}
				userName = subject;
			} else {
				boolean foundUserName = false;
				try {					
					LdapName ldapName = new LdapName(subject);
					List<Rdn> list = ldapName.getRdns();
					if (list != null) {
						for (Rdn rdn : list) {
							String type = rdn.getType();
							if (subjectDnAttribute.equalsIgnoreCase(type.toString()))  {
								Object value = rdn.getValue();
								if (value instanceof String) {
									userName = (String) value;
									foundUserName = true;									
									if (log.isDebugEnabled()) {
										log.debug("Success to retreive userName [" + userName + "].");
									}
									break;
								}		
							}
						}
					}					
				} catch (InvalidNameException e) {					
					log.info("subject [" + subject + "] is not valid name : [" + e.getMessage() + "].");
				}
				if (!foundUserName) {
					log.info("subject [" + subject + "] does not contain the required attribute [" + subjectDnAttributeConfiguration + "]. Return the whole subject.");
					userName = subject;
				}					
			}
			
		}
			
		if (log.isDebugEnabled()) {
			log.debug("getUserName(X509Certificate) - end; Ret is [" + userName + "].");
		}
        return userName;
    }

    private void setSubjectDnAttribute(String subjectDnAttributeConfiguration) {
		this.subjectDnAttributeConfiguration = subjectDnAttributeConfiguration;
		subjectDnAttribute = mapSubjectDnAttribute(subjectDnAttributeConfiguration);
		if (log.isDebugEnabled()) {
			log.debug("setSubjectDnAttribute(String) - end; subjectDnAttribute [" +  subjectDnAttribute + "]; subjectDnAttributeConfiguration [" +  subjectDnAttributeConfiguration + "]");
		}
    }
    
    

	private String mapSubjectDnAttribute(String subjectDnAttributeConfiguration) {
		String ret = null;
		if (subjectDnAttributeConfiguration != null) {
			if (EmailOptions.contains(subjectDnAttributeConfiguration.toLowerCase()))  {
				ret = EMAIL_SUBJECT_ATTR;				
			} else {
				ret = subjectDnAttributeConfiguration;
			}
		}
		return ret;
	}

	/**
	 * @param clientCert
	 * @return the whole SubjectSN of the X509Certificate
	 */
	protected String getSubjectDN(X509Certificate clientCert) {
		String subject = null;
		if (clientCert != null) {
			if ((clientCert.getSubjectDN()!= null) 
					&& (clientCert.getSubjectDN().getName() != null)) {
					subject = clientCert.getSubjectDN().getName();
			}  else {
				if (log.isDebugEnabled()) {
					log.debug("Can not getSubjectDN, SubjectDN is null");
				}
			}
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Can not getSubjectDN, clientCert is null");
			}
		}			
		if (log.isDebugEnabled()) {
			log.debug("getSubjectDN(X509Certificate) - end; Ret is [" + subject + "].");
		}
        return subject;
        
	}
}
