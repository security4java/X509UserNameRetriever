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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Implementation of <b>X509CertificateRetriever</b> that takes a X509Certificate from a HttpServletRequest attribute.
 * 
 * Allows to override the default attribute name.
 * Allows to take the X509Certificate from the attribute of String type or X509Certificate type.
 *     
 */
public class X509CertificateRetrieverImpl implements X509CertificateRetriever {
	
	private static final String DEFAULT_X509_CERTIFICATE_ATTRIBUTE_NAME = "javax.servlet.request.X509Certificate";

	private final String certAttrName;
	
	/**
	 * Logger for this class
	 */
	protected final Log logger = LogFactory.getLog(getClass());
	
	public X509CertificateRetrieverImpl(String certAttrName) {
		this.certAttrName = certAttrName == null ? DEFAULT_X509_CERTIFICATE_ATTRIBUTE_NAME : certAttrName;
	}
	public X509CertificateRetrieverImpl() {
		this(null);
	}
	
	public X509Certificate getClientCertificate(HttpServletRequest request) {
		X509Certificate ret = null;
		if (logger.isDebugEnabled()) {
			logger.debug("getClientCertificate(HttpServletRequest) - start");
		}

        Object attribute = request.getAttribute(certAttrName);
        if (attribute instanceof X509Certificate[] ) {
        	X509Certificate[] certs = (X509Certificate[]) attribute; 
            if (certs != null && certs.length > 0) {
            	ret = certs[0];
                if (logger.isDebugEnabled()) {
                    logger.debug("Success to get ClientCertificate [" + ret + "].");
                }            
            }
        } else if (attribute instanceof String) {
        	if (logger.isDebugEnabled()) {
        		logger.debug("Received a String. Try to convert the string [" + attribute + "] into certificate.");
        	}
            String certificateString = (String) attribute;
            byte[] certificateData = certificateString.getBytes();
            ByteArrayInputStream certificateInputStream = new ByteArrayInputStream(certificateData);
            X509Certificate certificates[] = null;
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certificateInputStream);
                certificates =  new X509Certificate[1];
                certificates[0] = x509Certificate;
                ret = certificates[0];
                if (logger.isDebugEnabled()) {
                    logger.debug("Success to convert string to client certificate [" + ret + "].");
                } 
            } catch(CertificateException e) {
           		logger.info("Failed to convert the string into certificate [" + attribute + "]. " + e.getMessage());
            }
        } else if (logger.isDebugEnabled()) {
        		logger.debug("No client certificate found in the request.");
        }

        return ret;
    }
	
	
}
