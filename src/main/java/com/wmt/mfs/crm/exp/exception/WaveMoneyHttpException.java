package com.wmt.mfs.crm.exp.exception;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mule.api.MuleEvent;
import org.mule.extension.validation.api.ValidationException;
import org.mule.extension.validation.api.ValidationResult; 

public class WaveMoneyHttpException extends ValidationException {

    private static Logger logger = LogManager.getLogger(WaveMoneyHttpException.class.getName());
    
    private static final long serialVersionUID = 1997753363232807009L;
     
    private Integer httpStatusCode;
    private String httpErorCode;
    private String errorMessage;
     
    public WaveMoneyHttpException(ValidationResult validationResult, MuleEvent event) {
        super(validationResult, event);
        logger.info("There was an error invoking request.");
    }
   
    public String getErrorMessage() {
        return errorMessage;
    }
 
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public Integer getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(Integer httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

	public String getHttpErorCode() {
		return httpErorCode;
	}

	public void setHttpErorCode(String httpErorCode) {
		this.httpErorCode = httpErorCode;
	} 
  
}