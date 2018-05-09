package com.wmt.mfs.crm.exp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwt.JwtClaims;
import org.mule.api.MuleEventContext;
import org.mule.api.lifecycle.Callable;
import org.mule.api.transport.PropertyScope;

import com.wmt.mfs.crm.exp.exception.WaveMoneyJWTException;

public class JWTHeaderToPropertiesFinOps implements Callable{
	
	private static Logger logger = LogManager.getLogger(JWTHeaderToPropertiesFinOps.class.getName());
	
	@Override
	public Object onCall(MuleEventContext eventContext) throws WaveMoneyJWTException {
		
		logger.info("=== JWT Header To Properties Fin Ops ===");
		
		JwtUtil ju = new JwtUtil();
		JwtClaims jwtClaims = ju.validateJWE4FinOpsAndReturnClaims((String)eventContext.getMessage().getInboundProperty("wmt-mfs"));
		
		logger.info("Claims: " + jwtClaims);
		 		
		String sessionId = (String) jwtClaims.getClaimValue("sessionId");
		String msisdn = (String) jwtClaims.getClaimValue("msisdn");
		String password = (String) jwtClaims.getClaimValue("password");
		String pin = (String) jwtClaims.getClaimValue("pin"); 
		
		eventContext.getMessage().setProperty("sessionId", sessionId , PropertyScope.OUTBOUND);
		eventContext.getMessage().setProperty("msisdn", msisdn , PropertyScope.OUTBOUND);
		eventContext.getMessage().setProperty("password", password , PropertyScope.OUTBOUND);
		eventContext.getMessage().setProperty("pin", pin , PropertyScope.OUTBOUND);
		eventContext.getMessage().setProperty("userType", "agent", PropertyScope.OUTBOUND);
		
		eventContext.getMessage().setInvocationProperty("CurrentProperties",(sessionId + "|" + msisdn + "|" + password + "|" + pin));
	 	
		return eventContext.getMessage().getPayload();
	}

}
