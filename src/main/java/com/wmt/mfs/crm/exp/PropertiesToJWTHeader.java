package com.wmt.mfs.crm.exp;

import java.util.StringTokenizer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwt.JwtClaims;
import org.mule.api.MuleEventContext;
import org.mule.api.lifecycle.Callable;
import org.mule.api.transport.PropertyScope;

import com.wmt.mfs.crm.exp.exception.WaveMoneyJWTException;

public class PropertiesToJWTHeader implements Callable{
	
	private static Logger logger = LogManager.getLogger(PropertiesToJWTHeader.class.getName());

	@Override
	public Object onCall(MuleEventContext eventContext) throws WaveMoneyJWTException {
		
		logger.info("=== Properties To JWT Header ==="); 
		
		return generateMFS(eventContext); 
	}
	
	public static Object generateMFS(MuleEventContext eventContext) throws WaveMoneyJWTException {
		
		String sessionId = (String)eventContext.getMessage().getInboundProperty("sessionId");
		String msisdn = (String)eventContext.getMessage().getInboundProperty("msisdn");
		String password = (String)eventContext.getMessage().getInboundProperty("password");
		String pin = (String)eventContext.getMessage().getInboundProperty("pin"); 
		
        if(sessionId == null || msisdn == null || password == null || pin == null){
			
			String currentProperties = eventContext.getMessage().getProperty("CurrentProperties", PropertyScope.SESSION);
			
			if(currentProperties != null)
			{
				
				StringTokenizer tokenizer = new StringTokenizer(currentProperties, "|");
				
				 sessionId = tokenizer.nextToken();
				 msisdn = tokenizer.nextToken();
				 password = tokenizer.nextToken();
				 pin = tokenizer.nextToken(); 
				 
				 logger.info("CurrentProperties: sessionId- " + sessionId + "| msisdn- " + msisdn + "| password- " + password + "| pin- " + pin);
			}else{
				logger.error("Lost CurrentProperties");
			}
		}
		
		eventContext.getMessage().setProperty("CurrentProperties",(sessionId + "|" + msisdn + "|" + password), PropertyScope.SESSION);
		 
		JwtClaims claims = new JwtClaims();
		claims.setClaim("sessionId",sessionId);
		claims.setClaim("msisdn", msisdn);
		claims.setClaim("password", password);
		claims.setClaim("pin", pin);
		
		logger.info("Claims: " + claims);
		
		JwtUtil ju = new JwtUtil();
		String jws = ju.createJWT(claims,eventContext);
		String jwt = ju.createJWE(jws,eventContext);
		
		eventContext.getMessage().setProperty("wmt-mfs", jwt, PropertyScope.OUTBOUND);
		
		return eventContext.getMessage().getPayload();
	}

}
