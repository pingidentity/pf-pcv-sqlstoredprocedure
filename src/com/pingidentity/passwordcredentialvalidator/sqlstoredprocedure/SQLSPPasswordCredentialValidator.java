/**
 * *************************************************************************
 * Copyright (C) 2014 Ping Identity Corporation All rights reserved.
 *
 * The contents of this file are subject to the terms of the Ping Identity
 * Corporation SDK Developer Guide.
 *
 *************************************************************************
 */
package com.pingidentity.passwordcredentialvalidator.sqlstoredprocedure;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.util.log.AttributeMap;

import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.PasswordValidationException;
import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;
import com.pingidentity.access.DataSourceAccessor;

/**
 * The SQLSPPasswordCredentialValidator class validates username and password credentials using a stored procedure against a SQL database via a JDBC driver.
 */
public class SQLSPPasswordCredentialValidator implements PasswordCredentialValidator {
	
	// initialize logger into PF
    private final Log logger = LogFactory.getLog(this.getClass());
    
    // instantiate and obtain config object
    private SQLSPPasswordCredentialValidatorConfiguration config = new SQLSPPasswordCredentialValidatorConfiguration();

	/**
	 * Validates the given username and password in the manner appropriate to the plugin implementation.
	 * 
	 * @param username
	 *            the given username/id
	 * @param password
	 *            the given password
	 * @return An AttributeMap with at least one entry representing the principal. The key of the entry does not matter,
	 *         so long as the map is not empty. If the map is empty or null, the username and password combination is
	 *         considered invalid.
	 * @throws PasswordValidationException
	 *             runtime exception when the validator cannot process the username and password combination due to
	 *             system failure such as data source off line, host name unreachable, etc.
	 */
    @Override
    public AttributeMap processPasswordCredential(String username, String password) throws PasswordValidationException {
    	logger.debug("processPasswordCredential :: BEGIN");
    	
        AttributeMap attrs = null;

        ResultSet results = null;
        PreparedStatement stmt = null;

        Connection conn = null;

        logger.debug("processPasswordCredential :: username: " + username);

        try {
            if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
                DataSourceAccessor dataSourceAccessor = new DataSourceAccessor();
                conn = dataSourceAccessor.getConnection(config.databaseDatasource);

                String spCall = "{call " + config.storedProcedureName + "(?,?)}";
                
                logger.debug("processPasswordCredential :: executing call: " + spCall);
                stmt = conn.prepareCall(spCall);
                stmt.setString(1, username);
                stmt.setString(2, password);
                results = stmt.executeQuery();

                if (results.next()) { // we have a response
                	
                    logger.debug("processPasswordCredential :: result: " + results.getInt(1));
                	if (results.getInt(1) == 1) { // true returned (ie return value of 1)
                        logger.debug("processPasswordCredential :: authentication successful");
                        attrs = new AttributeMap();
                        attrs.put("username", username);
                    } else { // false returned (ie return value of 0)
                        logger.debug("processPasswordCredential :: authentication failed");
                    }
            	} else {
            		// no response received
                    throw new PasswordValidationException("processPasswordCredential :: error validating username/password");
            	}

            }
        } catch (PasswordCredentialValidatorAuthnException ex) {
            logger.debug("processPasswordCredential :: Exception is: " + ex + ", with message: " + ex.getMessageKey());
            throw new PasswordCredentialValidatorAuthnException(false, ex.getMessageKey());
        } catch (Exception ex) {
            logger.debug("Exception is " + ex);
            throw new PasswordValidationException("processPasswordCredential :: other error validating username/password", ex);
        } finally {
            try {
                if (results != null) {
                    results.close();
                }
                
                if (stmt != null) {
                    stmt.close();
                }
                
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                logger.debug("processPasswordCredential :: Exception is " + ex);
                throw new PasswordValidationException("processPasswordCredential :: other SQL error validating username/password", ex);
            }
        }

        logger.debug("processPasswordCredential :: END");
        return attrs;
    }

	/**
	 * The getSourceDescriptor method returns the configuration details.
	 */
	@Override
	public PluginDescriptor getPluginDescriptor() {
		return config.getPluginDescriptor(this);
	}

	/**
	 * The configure method sets the configuration details.
	 */
	@Override
	public void configure(Configuration configuration) {
		config.configure(configuration);
	}    
}