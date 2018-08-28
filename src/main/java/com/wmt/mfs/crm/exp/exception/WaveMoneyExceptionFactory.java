package com.wmt.mfs.crm.exp.exception;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mule.api.MuleEvent;
import org.mule.extension.validation.api.ExceptionFactory;
import org.mule.extension.validation.api.ValidationResult;

import com.wavemoney.model.ExperienceLayerResponseError;


public class WaveMoneyExceptionFactory implements ExceptionFactory {

	private static Logger logger = LogManager.getLogger(WaveMoneyExceptionFactory.class.getName());

	@SuppressWarnings("unchecked")
	@Override
	public <T extends Exception> T createException(ValidationResult result, Class<T> exceptionClass, MuleEvent event) {
		
		logger.debug("Creating WaveMoneyException .. ");
		
		ExperienceLayerResponseError experienceLayerResponseError = event.getFlowVariable("ExperienceLayerResponseError");
 
		WaveMoneyException exception = new WaveMoneyException(result, event);
		 
		exception.setExperienceLayerResponseError(experienceLayerResponseError);
		
		logger.debug("WaveMoneyException has been created.");

		return (T) exception;
	}

	@Override
	public Exception createException(ValidationResult result, String exceptionClassName, MuleEvent event) {

		logger.debug("Creating WaveMoneyException .. ");
		
		ExperienceLayerResponseError experienceLayerResponseError = event.getFlowVariable("ExperienceLayerResponseError");
 
		WaveMoneyException exception = new WaveMoneyException(result, event);
		 
		exception.setExperienceLayerResponseError(experienceLayerResponseError);
		
		logger.debug("WaveMoneyException has been created.");
		
		return exception;
	}

}