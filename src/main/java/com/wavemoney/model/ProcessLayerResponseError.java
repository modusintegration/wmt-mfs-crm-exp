package com.wavemoney.model;

import java.io.Serializable;

public class ProcessLayerResponseError implements Serializable {
	 
	private static final long serialVersionUID = 123215435L;
	
	private ProcessLayerErrorCode errors; 
	private String codeStatus; 
	private String message;
	
	public ProcessLayerResponseError() {
		super();
	}
	
	public String getAmDocErrorMessage() {

		String returnValue = null;
		
		if(errors.getAmDocErrorCode() != null)
		{
			errors.getAmDocErrorCode().getErrorMessage();
		}

		return returnValue;
		
	}

	public ProcessLayerErrorCode getErrors() {
		return errors;
	}

	public void setErrors(ProcessLayerErrorCode errors) {
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