package com.wmt.mfs.crm.exp;

import java.util.StringTokenizer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mule.api.ExceptionPayload;
import org.mule.api.MuleEventContext;
import org.mule.api.lifecycle.Callable;
import org.mule.api.transport.PropertyScope;

import com.wmt.mfs.crm.exp.exception.WaveMoneyJWTException;

public class GenerateJWTHeaderAfterException implements Callable {

	private static Logger logger = LogManager.getLogger(GenerateJWTHeaderAfterException.class.getName());

	@Override
	public Object onCall(MuleEventContext eventContext) throws WaveMoneyJWTException {

		Object returnValue = null;
		
		logger.info("=== Generating WMT after Exception ==="); 
		
		String currentProperties = eventContext.getMessage().getProperty("CurrentProperties", PropertyScope.SESSION);

		if(currentProperties != null)
		{
			
			StringTokenizer tokenizer = new StringTokenizer(currentProperties, "|");
			
			String sessionId = tokenizer.nextToken();
			String msisdn = tokenizer.nextToken();
			String password = tokenizer.nextToken();
			String pin = tokenizer.nextToken(); 
			
			logger.info("MSISDN after Exception: " + msisdn);
			
			eventContext.getMessage().setProperty("sessionId", sessionId , PropertyScope.INBOUND);
			eventContext.getMessage().setProperty("msisdn", msisdn , PropertyScope.INBOUND);
			eventContext.getMessage().setProperty("password", password , PropertyScope.INBOUND);
			eventContext.getMessage().setProperty("pin", pin , PropertyScope.INBOUND);
	 	
		}else{
			logger.error("Lost CurrentProperties after Exception");
		}
		  
		ExceptionPayload exception = eventContext.getMessage().getExceptionPayload();

		if (exception.getException().getCause().getClass().getName()
				.compareTo("com.wmt.mfs.crm.exp.exception.WaveMoneyJWTException") == 0) {
			
			int counter = 1;
			
			boolean bExit = false;
			
			while (!bExit && counter <= 3) {
				
				counter = counter + 1;

				try {
					returnValue = PropertiesToJWTHeader.generateMFS(eventContext);
					bExit = true;

				} catch (WaveMoneyJWTException e1) {
					logger.error("Error Creating JWE: " + e1.getMessage(), e1);
				}
				
				try {
					Thread.sleep(5000);
				} catch (InterruptedException e1) {
					logger.error("Error with the pause" + e1.getMessage(), e1);
				}

			}

		} else {
			
			returnValue = PropertiesToJWTHeader.generateMFS(eventContext);
			
		}
		
		logger.info("WMT after Exception has been created");

		return returnValue;
	}

}
