package com.wmt.mfs.crm.exp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DbUtil {
	
	private static Logger logger = LogManager.getLogger(DbUtil.class.getName());
	
	public static void insertNonce(String uuidJti, long exp) {
		Connection psqlConnection = null;
 	    Statement insertQuery = null;
 	      try {
 	         Class.forName("org.postgresql.Driver");
 	         psqlConnection = DriverManager.getConnection("jdbc:postgresql://172.20.2.42:5432/SEC","secrw", "phpI8uGcPFXpG4B");
 	         psqlConnection.setAutoCommit(true);
 	         
 	         insertQuery = psqlConnection.createStatement();
 	         String insertSQL = "INSERT INTO public.nonce(nonce, expiration_time, created_by) VALUES('" + uuidJti + "', to_timestamp("+ exp +"), 'secrw')";
 	         int insertResult = insertQuery.executeUpdate( insertSQL );

 	        logger.info("insertResult: " + insertResult);
	         
 	         insertQuery.close();
 	         psqlConnection.close();
 	      } catch ( Exception e ) {
 	         System.err.println( e.getClass().getName()+": "+ e.getMessage() );
 	         System.exit(0);
 	      }
		
	}
	
	public static int deleteNonce(String jwtId) {
		int deleteResult = 0;
		Connection psqlConnection = null;
 	    Statement deleteQuery = null;
 	      try {
 	         Class.forName("org.postgresql.Driver");
 	         psqlConnection = DriverManager.getConnection("jdbc:postgresql://172.20.2.42:5432/SEC","secrw", "phpI8uGcPFXpG4B");
 	         psqlConnection.setAutoCommit(true);
 	         
 	         deleteQuery = psqlConnection.createStatement();
 	         String deleteSQL = "DELETE FROM public.nonce WHERE nonce='" + jwtId +"'";
 	         deleteResult = deleteQuery.executeUpdate( deleteSQL );

 	         System.out.println("deleteResult: " + deleteResult);
 	         System.out.println();
	         
 	         deleteQuery.close();
 	         psqlConnection.close();
 	      } catch ( Exception e ) {
 	         System.err.println( e.getClass().getName()+": "+ e.getMessage() );
 	      }
 	      return deleteResult;
		
	}

}
