package com.wavemoney.model;

import java.io.Serializable;

public class ExperienceLayerResponseError implements Serializable {
	 
	private static final long serialVersionUID = 123215435L;
	
	private ExperienceLayerErrorCode errors; 
	private String codeStatus; 
	private String message;
	
	public ExperienceLayerResponseError() {
		super();
	} 

	public ExperienceLayerErrorCode getErrors() {
		return errors;
	}
 
	public void setErrors(ExperienceLayerErrorCode errors) {
		this.errors = errors;
	}
 
	public String getCodeStatus() {
		return codeStatus;
	}

	public void setCodeStatus(String codeStatus) {
		this.codeStatus = codeStatus;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	} 
	
	
}