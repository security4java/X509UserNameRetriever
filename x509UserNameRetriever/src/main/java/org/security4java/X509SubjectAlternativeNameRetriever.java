/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.security4java;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Implementation of <b>X509UserNameRetriever</b> that takes a user name from the The Subject Alternative Name Field of the X509Certificate.
 * The user name is the unique part of information from the client certificate that used to identify the identity of the user. 
 * 
 * The extensions defined for X.509 v3 certificates provide methods for associating additional attributes with users or public keys 
 * and for managing relationships between certificate authorities. The Subject Alternative Name Field can contain the user name.
 * 
 * The Subject Alternative Name extension allows identities to be bound to the subject of the certificate. 
 * These identities may be included in addition to or in place of the identity in the subject field of the certificate. 
 * 
 * The Subject Alternative Name field can contain the following identities: 
 * 
 * 
 * Identity						Example
 * otherName					Other Name: Principal Name=bobOtherAltName@example.com
 * rfc822Name					RFC822 Name=bobRFC822AltName@example.com
 * dNSName						DNS Name=example1.com
 * x400Address
 * directoryName				Directory Address: E=bobDirAltName@example.com, CN=bob, OU=Gold Ballads, O=Gold Music, C=US
 * ediPartyName
 * uniformResourceIdentifier	URL=http://example.com/
 * iPAddress					IP Address=192.168.7.1
 * registeredID					Registered ID=1.2.3.4
 * 
 * To retrieve the user name from the Subject Alternative Name, you can use one of the identities. 
 * 
 * To retrieve the user name from the Subject Alternative Name using X509SubjectAlternativeNameRetriever, 
 * please provide the identity name for the constructor.
 * The identity name is a code letter based on a legend defined in the certificate itself.
 * 
 * For example, the Other Name Identity of Subject Alternative Name is used to hold the User Name.
 * Please provide "Other Name" or "Principal Name" for the constructor.
 * 
 * For example, the rfc822Name Identity of Subject Alternative Name is used to hold the User Name.
 * Please provide "RFC822 Name" for the constructor.
 * 
 */
public class X509SubjectAlternativeNameRetriever extends X509SubjectDnRetriever {
	private static final int NOT_EXISTING_TYPE = -1;


	/**
	 * Logger for this class
	 */
	protected final Log logger = LogFactory.getLog(getClass());
	
	
	private String alternativeNameConfiguration = null; 
   
	private int alternativeNameTypeValue = NOT_EXISTING_TYPE; 

	public X509SubjectAlternativeNameRetriever() {
		
	}
	
	public X509SubjectAlternativeNameRetriever(String alternativeNameConfiguration) {
        setSubjectAlternativeNameGeneralName(alternativeNameConfiguration);
    }

    
    
    /* (non-Javadoc)
     * @see org.apache.catalina.realm.X509SubjectDnRetriever#getUserName(java.security.cert.X509Certificate)
     */
    @SuppressWarnings({ "rawtypes" })
	public String getUserName(X509Certificate clientCert) {
		if (logger.isDebugEnabled()) {
			logger.debug("getUserName(X509Certificate) - start");
		}

		String userName = null;
		if (clientCert != null) {
			boolean foundUserName = false;
			if (alternativeNameTypeValue != NOT_EXISTING_TYPE) {
				try {
					if (clientCert.getSubjectAlternativeNames() != null) {
						Collection subjectAlternativeNames = clientCert.getSubjectAlternativeNames();
						Iterator iter = subjectAlternativeNames.iterator();
						/* 
						 * The method goes over collection of Subject Alternative Names.
						 * If the Subject Alternative Name type is equal to the configured
						 * predefined identity name, return the user name. 
						 */
						while (iter.hasNext()) {
							List subjectAlternativeName = (List) iter.next();
							Integer type = (Integer) subjectAlternativeName.get(0);
							if (type.intValue() == alternativeNameTypeValue) {
								Object subjectAlternativeNameValue = subjectAlternativeName.get(1);
								if (subjectAlternativeNameValue instanceof String) {
									userName = (String) subjectAlternativeNameValue;
									foundUserName = true;					
									break;
								} else if (subjectAlternativeNameValue instanceof byte[]) {
									byte[] subjectAlternativeNameValueBytes = (byte[]) subjectAlternativeNameValue;
									userName = getStringFromASNDerEncodedByteArray(subjectAlternativeNameValueBytes);
									if (userName != null) {
										foundUserName = true;
										break;
									}
								} else {
									if (logger.isInfoEnabled()) {
										logger.info("Can not get UserName, the subjectAlternativeName not supported [" + subjectAlternativeNameValue + "].");
									}
								}
							}
						}
					}
				} catch (CertificateParsingException e) {
					logger.info("Can not get UserName, can not get subjectAlternativeNames from certificate [" + e.getMessage() + "].");
				}				

				
			} else {
				if (logger.isDebugEnabled()) {
					logger.debug("Can not get UserName, generalName is null");
				}
			}
			if (!foundUserName) {
				logger.info("Can not found userName as part of subjectAlternativeName [" + alternativeNameConfiguration + "]. Return the whole subject.");
				userName = getSubjectDN(clientCert);
			}					

		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("Can not get UserName, clientCert is null");
			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("getUserName(X509Certificate) - end; Ret is [" + userName + "].");
		}

		return userName;
	}



	

    /**
     * The method converts the provided configuration into the predefined identity name type. 
     * @param alternativeNameConfiguration
     */
    private void setSubjectAlternativeNameGeneralName(String alternativeNameConfiguration) {
		if (logger.isDebugEnabled()) {
			logger.debug("setSubjectAlternativeNameGeneralName(String) - start; alternativeName [" +  alternativeNameConfiguration + "].");
		}
		this.alternativeNameConfiguration = null;
		alternativeNameTypeValue = NOT_EXISTING_TYPE;
		
		if (alternativeNameConfiguration != null) {
			this.alternativeNameConfiguration = alternativeNameConfiguration;
			String alternativeNameConfigurationLowerCase = alternativeNameConfiguration.toLowerCase();
			if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.otherName.equalsIgnoreCase (alternativeNameConfiguration)) 
					|| (X509SubjectAlternativeNameConstants.OtherNameOptions.contains(alternativeNameConfigurationLowerCase))) {
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.otherName.ordinal();				
			} else if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.rfc822Name.equalsIgnoreCase (alternativeNameConfiguration)) 
					|| (X509SubjectAlternativeNameConstants.RFC822NameOptions.contains(alternativeNameConfigurationLowerCase))) {
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.rfc822Name.ordinal();				
			} else if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.dNSName.equalsIgnoreCase (alternativeNameConfiguration)) 
					|| (X509SubjectAlternativeNameConstants.DNSNameOptions.contains(alternativeNameConfigurationLowerCase))) {
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.dNSName.ordinal();				
			} else if (X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.x400Address.equalsIgnoreCase (alternativeNameConfiguration)) {
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.x400Address.ordinal();				
			} else if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.directoryName.equalsIgnoreCase (alternativeNameConfiguration)) 
					|| (X509SubjectAlternativeNameConstants.DirectoryNameOptions.contains(alternativeNameConfigurationLowerCase))) {
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.directoryName.ordinal();				
			} else if (X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.ediPartyName.equalsIgnoreCase (alternativeNameConfiguration)) {
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.ediPartyName.ordinal();				
			} else if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.uniformResourceIdentifier.equalsIgnoreCase (alternativeNameConfiguration)) 
					|| (X509SubjectAlternativeNameConstants.UriOptions.contains(alternativeNameConfigurationLowerCase))) {				
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.uniformResourceIdentifier.ordinal();				
			} else if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.iPAddress.equalsIgnoreCase (alternativeNameConfiguration)) 
					|| (X509SubjectAlternativeNameConstants.IPAddressOptions.contains(alternativeNameConfigurationLowerCase))) {					
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.iPAddress.ordinal();				
			} else if ((X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.registeredID.equalsIgnoreCase (alternativeNameConfiguration)) 
				|| (X509SubjectAlternativeNameConstants.RegisteredIDOptions.contains(alternativeNameConfigurationLowerCase))) {									
				alternativeNameTypeValue = X509SubjectAlternativeNameConstants.X509SubjectAlternativeNameGeneralNames.registeredID.ordinal();				
			} else {
				try {
					alternativeNameTypeValue = (new Integer(alternativeNameConfiguration)).intValue();
				}catch (NumberFormatException e) {
					alternativeNameTypeValue = NOT_EXISTING_TYPE;
				}
			}
		
		}
		if (logger.isDebugEnabled()) {
			logger.debug("setSubjectAlternativeNameGeneralName(String) - end; alternativeName [" +  alternativeNameConfiguration + "], alternativeNameType [" +  alternativeNameTypeValue + "].");
		}
    }


	/**
	 * The method converts ASNDerEncodedByteArray into String
	 * @param byteArray
	 * @return String 
	 */
	private String getStringFromASNDerEncodedByteArray(byte[] byteArray) {
		if (logger.isDebugEnabled()) {
			logger.debug("getStringFromASNDerEncodedByteArray(byte[]) - start");
		}

		String ret = null;
		try {	
			ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(byteArray));
			DERObject derObject = asn1InputStream.readObject();
			ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(derObject);
			Object objectValue = asn1Sequence.getObjectAt(1);
			if (objectValue instanceof ASN1TaggedObject) {
				ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) objectValue;
				try {
					if (logger.isDebugEnabled()) {
						logger.debug("Try to get string from DERUTF8String.");
					}
					DERObject derTaggedObject = asn1TaggedObject.getObject();
					DERUTF8String derUtf8String = DERUTF8String.getInstance(derTaggedObject);
					ret = derUtf8String.getString();
				} catch (IllegalArgumentException e) {
					if (logger.isDebugEnabled()) {
						logger.debug("Can not get String From DERUTF8String, [" + e.getMessage() + "].");
					}
				}				
			}
		} catch (Exception e) {
			if (logger.isInfoEnabled()) {
				logger.info("Can not get String From ASNDerEncoded ByteArray, [" + e.getMessage() + "].");
			}
		}

		if (logger.isDebugEnabled()) {
			logger.debug("getStringFromASNDerEncodedByteArray(byte[]) - end. Ret is [" + ret + "].");
		}
		return ret;

	}

	
	/* (non-Javadoc)
	 * @see org.apache.catalina.realm.X509SubjectDnRetriever#setX509UserNameRetrieverConfiguration(java.lang.String)
	 */
	public void setX509UserNameRetrieverConfiguration(String x509UserNameRetrieverConfiguration) { 
		 setSubjectAlternativeNameGeneralName(x509UserNameRetrieverConfiguration);
		
	}
	

}
