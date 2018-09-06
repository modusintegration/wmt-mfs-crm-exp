package com.wavemoney.validator;

 
import java.io.IOException;
 

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mule.api.MuleEvent;
import org.mule.extension.validation.api.ValidationResult;
import org.mule.extension.validation.api.Validator;
import org.mule.extension.validation.internal.ImmutableValidationResult;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wavemoney.model.ExperienceLayerErrorCode;
import com.wavemoney.model.ExperienceLayerResponseError; 
import com.wavemoney.model.ProcessLayerResponseError; 

public class WaveMoneyRestProcessValidator implements Validator {
	
	private static Logger logger = LogManager.getLogger(WaveMoneyRestProcessValidator.class.getName());

	@Override
	public ValidationResult validate(MuleEvent event) {
  
		ValidationResult result = null;
		
		// Create ExperienceLayerErrorCode Objects
		
		ExperienceLayerResponseError expirienceLayerResponseError = null;
		
		ExperienceLayerErrorCode experienceLayerErrorCode = null;
		
		// Get HTTP Status returned
		
		Integer httpStatus = (Integer) event.getMessage().getInboundProperty("http.status");
		
		
		if(httpStatus != null && httpStatus instanceof Integer)
		{
			
			if(httpStatus == 200)
			{
				return ImmutableValidationResult.ok();
			}
			else
			{
				
				// Get Payload
				
				Object payload = null;
				
				try {
					
					payload = event.getMessage().getPayloadAsString();
					
				} catch (Exception e) {
					
					logger.error(e.getMessage(),e);
					
					experienceLayerErrorCode = new ExperienceLayerErrorCode();
					experienceLayerErrorCode.setFlowName((String) event.getFlowVariable("flowName"));
					experienceLayerErrorCode.setCategory((String) event.getFlowVariable("metricCategory"));
					experienceLayerErrorCode.setErrorCode("CEL0005");
					experienceLayerErrorCode.setHttpStatus(500);
					experienceLayerErrorCode.setErrorMessage(e.getMessage()); 
					experienceLayerErrorCode.setProcessLayerErrorCode(null);
					 
					expirienceLayerResponseError = new ExperienceLayerResponseError();
					expirienceLayerResponseError.setCodeStatus(experienceLayerErrorCode.getErrorCode());
					expirienceLayerResponseError.setMessage(experienceLayerErrorCode.getErrorMessage());
					expirienceLayerResponseError.setErrors(experienceLayerErrorCode);
					 
					event.setFlowVariable("ExperienceLayerResponseError", expirienceLayerResponseError);
					
				    result = ImmutableValidationResult.error(experienceLayerErrorCode.getErrorMessage());
				    
				    return result;
				}
				
				logger.info("Processing Response: " + (String) event.getMessage().getPayload());
				
				ObjectMapper om = new ObjectMapper();
				  
				ProcessLayerResponseError response;
				
				try {
					
					response = om.readValue((String) payload, ProcessLayerResponseError.class);
					
					experienceLayerErrorCode = new ExperienceLayerErrorCode();
					
					experienceLayerErrorCode.setFlowName((String) event.getFlowVariable("flowName"));
					experienceLayerErrorCode.setCategory((String) event.getFlowVariable("metricCategory"));
					experienceLayerErrorCode.setErrorCode("CEL0003");
					experienceLayerErrorCode.setHttpStatus(response.getErrors().getHttpStatus());
					experienceLayerErrorCode.setErrorMessage("Process Layer returned error: " + response.getMessage()); 
					experienceLayerErrorCode.setProcessLayerErrorCode(response.getErrors());
					 
					expirienceLayerResponseError = new ExperienceLayerResponseError();
					expirienceLayerResponseError.setCodeStatus(experienceLayerErrorCode.getErrorCode());
					
					if(response.getErrors().getAmDocErrorCode() !=null)
					{
						expirienceLayerResponseError.setMessage(response.getErrors().getAmDocErrorCode().getErrorMessage());
					}
					else
					{
						expirienceLayerResponseError.setMessage(experienceLayerErrorCode.getErrorMessage());
						
					}
					
					expirienceLayerResponseError.setErrors(experienceLayerErrorCode);
					 
					event.setFlowVariable("ExperienceLayerResponseError", expirienceLayerResponseError);
					
				    result = ImmutableValidationResult.error(experienceLayerErrorCode.getErrorMessage());
				    
					
				} catch (IOException e) {
					
					experienceLayerErrorCode = new ExperienceLayerErrorCode();
					experienceLayerErrorCode.setFlowName((String) event.getFlowVariable("flowName"));
					experienceLayerErrorCode.setCategory((String) event.getFlowVariable("metricCategory"));
					experienceLayerErrorCode.setErrorCode("CEL0002");
					experienceLayerErrorCode.setHttpStatus(500);
					experienceLayerErrorCode.setErrorMessage(e.getMessage()); 
					experienceLayerErrorCode.setProcessLayerErrorCode(null);
					 
					expirienceLayerResponseError = new ExperienceLayerResponseError();
					expirienceLayerResponseError.setCodeStatus(experienceLayerErrorCode.getErrorCode());
					expirienceLayerResponseError.setMessage(experienceLayerErrorCode.getErrorMessage());
					expirienceLayerResponseError.setErrors(experienceLayerErrorCode);
					 
					event.setFlowVariable("ExperienceLayerResponseError", expirienceLayerResponseError);
					
				    result = ImmutableValidationResult.error(experienceLayerErrorCode.getErrorMessage());
				    
				    logger.error(e.getMessage(),e);
					
				}
				 
			} 
			
		}
		else
		{
			experienceLayerErrorCode = new ExperienceLayerErrorCode();
			experienceLayerErrorCode.setFlowName((String) event.getFlowVariable("flowName"));
			experienceLayerErrorCode.setCategory((String) event.getFlowVariable("metricCategory"));
			experienceLayerErrorCode.setErrorCode("CEL0001");
			experienceLayerErrorCode.setHttpStatus(500);
			experienceLayerErrorCode.setErrorMessage("Error Getting HTTP status from Experience Layer");
			experienceLayerErrorCode.setProcessLayerErrorCode(null);
			
			expirienceLayerResponseError = new ExperienceLayerResponseError();
			expirienceLayerResponseError.setCodeStatus(experienceLayerErrorCode.getErrorCode());
			expirienceLayerResponseError.setMessage(experienceLayerErrorCode.getErrorMessage());
			expirienceLayerResponseError.setErrors(experienceLayerErrorCode);
			 
			event.setFlowVariable("ExperienceLayerResponseError", expirienceLayerResponseError);
			
		    result = ImmutableValidationResult.error(experienceLayerErrorCode.getErrorMessage());
			 
		    
		}
		
		return result; 
 
	}

}