package com.wmt.mfs.crm.exp.exception;

import org.mule.api.MuleEvent;
import org.mule.extension.validation.api.ValidationException;
import org.mule.extension.validation.api.ValidationResult;
 
import com.wavemoney.model.ExperienceLayerResponseError;

public class WaveMoneyException extends ValidationException {

	private static final long serialVersionUID = 1997753363232807009L;
	 
	ExperienceLayerResponseError experienceLayerResponseError;
	 
	public WaveMoneyException(ValidationResult validationResult, MuleEvent event) {
		super(validationResult, event);
	}

	public ExperienceLayerResponseError getExperienceLayerResponseError() {
		return experienceLayerResponseError;
	}

	public void setExperienceLayerResponseError(ExperienceLayerResponseError experienceLayerResponseError) {
		this.experienceLayerResponseError = experienceLayerResponseError;
	}

	 
}