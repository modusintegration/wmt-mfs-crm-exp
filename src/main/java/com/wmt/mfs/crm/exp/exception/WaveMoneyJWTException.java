package com.wmt.mfs.crm.exp.exception;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WaveMoneyJWTException extends Exception {

	private static Logger logger = LogManager.getLogger(WaveMoneyJWTException.class.getName());

	private static final long serialVersionUID = 1997753363232807009L;

	private Integer httpStatusCode;
	private String jwtCode;
	private String errorMessage;

	public WaveMoneyJWTException(Exception e) {
		super(e);
		logger.info("There was an error with JWT Util.");
	}

	public WaveMoneyJWTException(Integer httpStatusCode, String jwtCode, String errorMessage, Exception e) {
		super(e);
		this.jwtCode = jwtCode;
		this.errorMessage = errorMessage;
		this.httpStatusCode = httpStatusCode;
		logger.info("There was an error with JWT Util.");
	}
	
	public WaveMoneyJWTException(Integer httpStatusCode, String jwtCode, String errorMessage) {
		super();
		this.jwtCode = jwtCode;
		this.errorMessage = errorMessage;
		this.httpStatusCode = httpStatusCode;
		logger.info("There was an error with JWT Util.");
	}

	public Integer getHttpStatusCode() {
		return httpStatusCode;
	}

	public void setHttpStatusCode(Integer httpStatusCode) {
		this.httpStatusCode = httpStatusCode;
	}

	public String getJwtCode() {
		return jwtCode;
	}

	public void setJwtCode(String jwtCode) {
		this.jwtCode = jwtCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

}