package com.wavemoney.util;
  

public class TransformerUtil {

	 
	public static Object getExceptionMessage(Exception exception) throws Exception {
		 
		return exception.getMessage();

	}
	
	public static Object getCauseMessage(Exception exception) throws Exception {
		 
		return exception.getCause().getMessage();

	}
	

}