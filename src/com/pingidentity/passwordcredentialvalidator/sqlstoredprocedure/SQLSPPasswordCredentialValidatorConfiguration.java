package com.pingidentity.passwordcredentialvalidator.sqlstoredprocedure;

import java.util.HashSet;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.JdbcDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;

/**
 * The SQLPasswordCredentialValidatorConfiguration class contains PingFederate web GUI configuration parameters for the SQLPasswordCredentialValidator.
 */
public class SQLSPPasswordCredentialValidatorConfiguration {

	// initialize configuration object
    protected Configuration configuration = null;
    
    private static final String JDBC_DATASOURCE = "JDBC Datasource";
    private static final String JDBC_DATASOURCE_DESC = "The JDBC DataSource.";
    private static final String VERIFY_PASSWORD_STORED_PROCEDURE = "Verify Password Stored Procedure Name";
    private static final String VERIFY_PASSWORD_STORED_PROCEDURE_DESC = "The name of the stored procedure to execute. Takes a username and a password as the two parameters returns 0 for failure, 1 for success.";

    protected String databaseDatasource = null;
    protected String storedProcedureName = null;
    protected String successResponse = null;
    
	/**
	 * This method is called by the PingFederate server to push configuration values entered by the administrator via
	 * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
	 * should use the {@link Configuration} parameter to configure its own internal state as needed. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your plugin implementation this method will be
	 * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your plugin implementation instance until after
	 * creation and configuration is completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered by the user via the GUI.
	 */    
    public void configure(Configuration configuration) {
        this.databaseDatasource = configuration.getFieldValue(JDBC_DATASOURCE);
        this.storedProcedureName = configuration.getFieldValue(VERIFY_PASSWORD_STORED_PROCEDURE);
    }

	/**
	 * Returns the {@link PluginDescriptor} that describes this plugin to the PingFederate server. This includes how
	 * PingFederate will render the plugin in the administrative console, and metadata on how PingFederate will treat
	 * this plugin at runtime.
	 * 
	 * @return A {@link PluginDescriptor} that describes this plugin to the PingFederate server.
	 */    
    public PluginDescriptor getPluginDescriptor(SQLSPPasswordCredentialValidator scv) {
    	RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();
    	
    	GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
		guiDescriptor.setDescription(buildName());
		
        FieldDescriptor jdbcDS = new JdbcDatastoreFieldDescriptor(JDBC_DATASOURCE, JDBC_DATASOURCE_DESC);
        jdbcDS.addValidator(requiredFieldValidator);
        guiDescriptor.addField(jdbcDS);

        TextFieldDescriptor spNameDescriptor = new TextFieldDescriptor(VERIFY_PASSWORD_STORED_PROCEDURE, VERIFY_PASSWORD_STORED_PROCEDURE_DESC);
        spNameDescriptor.addValidator(requiredFieldValidator);
        spNameDescriptor.setDefaultValue("sp_verifypassword");
        guiDescriptor.addField(spNameDescriptor);

        PluginDescriptor pluginDescriptor = new PluginDescriptor("SQL Stored Procedure Password Credential Validator", scv, guiDescriptor);
		//pluginDescriptor.setAttributeContractSet(Collections.singleton(USERNAME));
        HashSet<String> attributes = new HashSet<String>();
        attributes.add("username");
        pluginDescriptor.setAttributeContractSet(attributes);
		pluginDescriptor.setSupportsExtendedContract(false);
    	
		return pluginDescriptor;
    }
    

	/**
	 * The buildName method returns the name and version from the information in META-INF/MANIFEST.MF, in order to name the jar within this package.
	 * 
	 * @return name of the plug-in
	 */
	private String buildName() {
		Package plugin = SQLSPPasswordCredentialValidator.class.getPackage();
		String title = plugin.getImplementationTitle(); // Implementation-Title
		String version = plugin.getImplementationVersion(); // Implementation-Version:
		String name = title + " " + version;
		return name;
	}     
}