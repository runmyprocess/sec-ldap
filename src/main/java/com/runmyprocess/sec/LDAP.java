package com.runmyprocess.sec;

import java.io.File;
import java.util.logging.Logger;

import javax.naming.directory.*;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SimpleBindRequest;

import com.unboundid.ldap.sdk.*;
import com.unboundid.ldif.LDIFException;
import org.runmyprocess.json.JSONArray;
import org.runmyprocess.json.JSONObject;

/**
 *
 * @author Malcolm Haslam <mhaslam@runmyprocess.com>
 *
 * Copyright (C) 2014 Fujitsu RunMyProcess
 *
 * This file is part of RunMyProcess SEC.
 *
 * RunMyProcess SEC is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License Version 2.0 (the "License");
 *
 *   You may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

public class LDAP implements ProtocolInterface{
    private static final Logger LOGGER = Logger.getLogger(
            Thread.currentThread().getStackTrace()[0].getClassName() );
    static DirContext ldapContext;
    private Response response = new Response();

    private LDAPConnection connection;

    private enum Operation {
        SEARCH, ADD, MODIFY, DELETE
    }

    public LDAP() {

        // TODO Auto-generated constructor stub
    }

    /**
     * Manages errors
      * @param error
     * @return  an error jsonObject
     */
    private JSONObject LDAPAgentError(String  error){
        response.setStatus(400);//sets the return status to internal server error
        JSONObject errorObject = new JSONObject();
        errorObject.put("error", error);
        response.setData(errorObject);
        return errorObject;
    }

    /**
     * Creates a connection to LDAP
     * @param conf  the configuration information from the loaded config file
     * @param user  the connection dn
     * @param password  the connection password
     * @throws LDAPException
     */
    private void newConnection(Config conf, String user, String password)
            throws LDAPException, LDIFException {
        // host, port, username and password
        final LDAPConnectionOptions connectionOptions =
                new LDAPConnectionOptions();
        int connectionTimeoutMillis = 5000;
        connectionOptions.setConnectTimeoutMillis(connectionTimeoutMillis);
        LOGGER.info("Connecting to:" + conf.getProperty("host") + "Port" + conf.getProperty("port")) ;
        this.connection= new LDAPConnection(connectionOptions,conf.getProperty("host"),
                Integer.parseInt(conf.getProperty("port")));
        if (user != null && !user.isEmpty()){

            SimpleBindRequest bindRequest = new SimpleBindRequest(user,password);
            bindRequest.setResponseTimeoutMillis(10000);

            // exceptions ignored for this example
            BindResult bindResult = connection.bind(bindRequest);
            if(bindResult.getResultCode().equals(ResultCode.SUCCESS))
            {
                LOGGER.info("The BIND request was successful");
                if(bindResult.hasResponseControl())
                {
                    // Retrieve and process the response control.
                }
            }
        }
    }

    /**
     * Searches for data in LDAP
     * @param jsonObject the jsonObject containing the request information
     * @throws LDAPSearchException
     */
    private void search( JSONObject jsonObject)
            throws LDAPSearchException {
        SearchResult searchResult;
        if (this.connection.isConnected()) {

            String baseDN = jsonObject.getString("baseDN");
            String filter =  jsonObject.getString("filter");

            searchResult = this.connection.search(baseDN, SearchScope.ONE, filter);

            response.setStatus(200);
            JSONObject reply = new JSONObject();
            reply.put("Result",searchResult.getSearchEntries().toString());
            response.setData(reply);

        } else{
            LDAPAgentError("LDAP Connection Lost");
        }
    }

    /**
     * Adds a registry
     * @param jsonObject the jsonObject containing the request information
     * @throws Exception
     */
    private void addRequest( JSONObject jsonObject)
            throws LDIFException, LDAPException {

        if (this.connection.isConnected()) {
            JSONArray jsonArr=  jsonObject.getJSONArray("ldif");
            String[] ldifLines=new String[jsonArr.size()];

            for(int i=0;i<jsonArr.size();i++)  {
                ldifLines[i]=jsonArr.get(i).toString();
            }

            LDAPResult result = connection.add(new AddRequest(ldifLines));
            connection.close();//close connection after request

            response.setStatus(200);
            JSONObject reply = new JSONObject();
            reply.put("Result", result.toString());
            response.setData(reply);
        }
    }

    /**
     * Modifies a registry
     * @param jsonObject the jsonObject containing the request information
     * @throws Exception
     */
    private void modifyRequest(JSONObject jsonObject)
            throws LDAPException, LDIFException {

        if (this.connection.isConnected()) {

            JSONArray jsonArr=  jsonObject.getJSONArray("ldif");
            String[] ldifLines=new String[jsonArr.size()];

            for(int i=0;i<jsonArr.size();i++)  {
                ldifLines[i]=jsonArr.get(i).toString();
            }

            LDAPResult result = connection.modify(new ModifyRequest(ldifLines));
            connection.close();//close connection after request

            response.setStatus(200);
            JSONObject reply = new JSONObject();
            reply.put("Result", result.toString());
            response.setData(reply);

        }
    }

    /**
     * Deletes a registry
     * @param jsonObject the jsonObject containing the request information
     * @throws Exception
     */
    private void deleteRequest( JSONObject jsonObject)
            throws LDAPException {

        if (this.connection.isConnected()) {

            String deleteDN=  jsonObject.getString("deleteDN");
            LDAPResult result = connection.delete(new DeleteRequest(deleteDN));
            connection.close();//close connection after request

            response.setStatus(200);
            JSONObject reply = new JSONObject();
            reply.put("Result", result.toString());
            response.setData(reply);

        }
    }

    /**
     * Recieves the information, reads the configuration information and calls the appropriate function
     * @param jsonObject
     * @param configPath
     */
    @Override
    public void accept(JSONObject jsonObject,String configPath) {

        LOGGER.info("Searching for config file...");
        Config conf = new Config("configFiles"+File.separator+ "LDAP.config",true);//sets the config info
        LOGGER.info("Config file found  ");
        try {

            this.newConnection(conf, jsonObject.getString("userDN"), jsonObject.getString("password"));
            Operation operation = Operation.valueOf(jsonObject.getString("operation"));
            try{
                switch(operation) {
                    case SEARCH:
                        this.search(jsonObject);
                        break;
                    case ADD:
                        this.addRequest(jsonObject);
                        break;
                    case MODIFY:
                        this.modifyRequest(jsonObject);
                        break;
                    case DELETE:
                        this.deleteRequest(jsonObject);
                        break;
                    default:throw new Exception("The operation "+jsonObject.getString("operation")+" is unknown");
                }
            }catch (LDAPException e){
                 LDAPAgentError(e.toString()) ;
            } catch (LDIFException e){
                LDAPAgentError(e.toString()) ;
            }
            this.connection.close();

        }catch (LDAPException e){
            LDAPAgentError(e.toString()) ;
        } catch (LDIFException e){
            LDAPAgentError(e.toString()) ;
        }catch (Exception e){
            LDAPAgentError(e.getLocalizedMessage());
        }


    }

    /**
     * Returns the response value
     * @return  response
     */
    @Override
    public Response getResponse() {
        return response;
    }

}






