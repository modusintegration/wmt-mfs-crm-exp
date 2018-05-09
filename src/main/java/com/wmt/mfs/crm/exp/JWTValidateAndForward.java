package com.wmt.mfs.crm.exp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwt.JwtClaims;
import org.mule.api.MuleEventContext;
import org.mule.api.lifecycle.Callable;
import org.mule.api.transport.PropertyScope;

public class JWTValidateAndForward implements Callable{
	
	private static Logger logger = LogManager.getLogger(JWTValidateAndForward.class.getName());
	
	@Override
	public Object onCall(MuleEventContext eventContext) throws Exception {
		
		String jwt = (String)eventContext.getMessage().getInboundProperty("wmt-mfs");
		JwtUtil ju = new JwtUtil();
		JwtClaims jwtClaims = ju.validateJWEAndReturnClaims(jwt);
		
		logger.info("Claims: " + jwtClaims);
		
		eventContext.getMessage().setProperty("wmt-mfs", jwt, PropertyScope.OUTBOUND);
				
		return eventContext.getMessage().getPayload();
	}
}
