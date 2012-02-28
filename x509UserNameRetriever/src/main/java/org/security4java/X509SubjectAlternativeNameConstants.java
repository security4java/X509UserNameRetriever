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

import java.util.Arrays;
import java.util.List;

/**
 * The class contains lists of constants used by <b>X509SubjectAlternativeNameRetriever</b>
 * The values are based on a legend defined in the certificate itself.
 * It tested with the following browsers: IE, FF and Chrome
 * For new browsers may be will required to add a new legend value to the list.
 * During the creation of <b>X509SubjectAlternativeNameRetriever</b> the constants are 
 * replaced to a subject alternative identity name. 
 */

public class X509SubjectAlternativeNameConstants {
	

	public enum X509UserNameRetrieveField {
		SubjectDN, SubjectAlternativeName;		
		public boolean equals(final String str) {
			return name().equals(str);
		}
	}	
		
	public enum X509SubjectAlternativeNameGeneralNames {
		
		otherName, // byte arrays containing the ASN.1 DER encoded form 
		rfc822Name, // String
		dNSName, // String
		x400Address, // byte arrays containing the ASN.1 DER encoded form 
		directoryName, // String: RFC 2253 string format
		ediPartyName, // byte arrays containing the ASN.1 DER encoded form 
		uniformResourceIdentifier, // String
		iPAddress, // String: IPv4 address - dotted quad notation, IPv6 address - form "a1:a2:...:a8"
		registeredID;
		
		public boolean equals(final String str) {
			return name().equals(str);
		}
		
		public boolean equalsIgnoreCase(final String str) {
			return name().equalsIgnoreCase(str);
		}
	}
	

	// !!! important - set value only in lower case !!!
	
	// Subject Alternative Name
	public static final List<String> OtherNameOptions = Arrays.asList("other name", "principalname", "principal name", "microsoft principal name") ;
	public static final List<String> RFC822NameOptions = Arrays.asList("rfc822 name", "rfc822name", "emailaddress", "email address", "e-mail address", "e-mailaddress") ;
	public static final List<String> DNSNameOptions = Arrays.asList("dns name", "dnsname") ;
	// x400Address - empty
	public static final List<String> DirectoryNameOptions = Arrays.asList("directory address", "directory address", "x500 name", "x500name", "x.500 name", "x.500name") ;
	// ediPartyName - empty
	public static final List<String> UriOptions = Arrays.asList("url", "uri") ;
	public static final List<String> IPAddressOptions = Arrays.asList("ip address", "ipaddress");
	public static final List<String> RegisteredIDOptions = Arrays.asList("registered id", "registeredid","registered oid", "registeredoid");

}
