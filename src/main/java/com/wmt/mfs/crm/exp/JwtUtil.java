package com.wmt.mfs.crm.exp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.mule.api.MuleEventContext;

import com.wmt.mfs.crm.exp.exception.WaveMoneyJWTException;

public class JwtUtil {

//	private static String publicKey = "src/main/resources/mfsKeystore.jks";
//	 private static String publicKey =
//	 "/opt/mule-enterprise-standalone-3.9.0/apps/wmt-mfs-crm-exp/classes/mfsKeystore.jks";
	 private static String publicKey = "mfsKeystore.jks";
	private static Logger logger = LogManager.getLogger(JwtUtil.class.getName());
	
	public static final String CRM_PROPERTIES = "wmt-mfs-crm-exp.properties";
	public static final String CRM_SEC_PROPERTIES = "wmt-mfs-crm-exp-sec.properties";

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		JwtClaims claims = new JwtClaims();
		claims.setClaim("sessionId", "sessionId1");
		claims.setClaim("msisdn", "9790303034");
		claims.setClaim("password", "3693");
		claims.setClaim("pin", "3693");

		JwtUtil ju = new JwtUtil();

		String jwt = null;
		try {
			jwt = ju.createJWT(claims,null);
		} catch (WaveMoneyJWTException e1) {
			logger.error("Create JWT Exception: " + e1.getMessage());
		}

		logger.info("JWT Header created: " + jwt);

		try {
			logger.info("JWT Claims read: " + ju.validateJWTAndReturnClaims(jwt));
		} catch (WaveMoneyJWTException e2) {
			logger.error("JWT Claims read Exception: " + e2.getMessage());
		}
	 
		String jwe = null;
		
		try {
			jwe = ju.createJWE(jwt, null);
		} catch (WaveMoneyJWTException e1) {
			logger.error("Creating JWE Exception: " + e1.getMessage());
		}
		
		logger.info("JWE: " + jwe);

		try {
			logger.info("JWE-JWS-JWT Claims read: " + ju.validateJWEAndReturnClaims(jwe));
		} catch (WaveMoneyJWTException e1) {
			logger.error("Creating JWE Exception: " + e1.getMessage());
		}

	}

	/**
	 * @param args
	 */

	String createJWE(String jws, MuleEventContext eventContext) throws WaveMoneyJWTException {

		String jwt = null;
		 
		logger.info("*** Creating JWE ***");
		
		logger.debug("Mule Payload Class: " + eventContext.getMessage().getPayload().getClass().getName());
		logger.debug("Mule Payload Value: " + eventContext.getMessage().getPayloadForLogging());
		 
		try {

			// The outer JWT is a JWE
			JsonWebEncryption jwe = new JsonWebEncryption();

			// The output of the RSA key agreement will encrypt a randomly
			// generated
			// content encryption key
			jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);

			// The content encryption key is used to encrypt the payload
			// with a composite AES-CBC / HMAC SHA2 encryption algorithm
			String encAlg = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
			jwe.setEncryptionMethodHeaderParameter(encAlg);

			Util u = new Util();
			// We encrypt to the receiver using their public key
			jwe.setKey((RSAPublicKey) getPublicKey(publicKey, u.getProperty("jks.public.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.public.jwt.encrypt.alias", CRM_PROPERTIES)));
			jwe.setKeyIdHeaderValue("mfs");

			// A nested JWT requires that the cty (Content Type) header be set
			// to
			// "JWT" in the outer JWT
			jwe.setContentTypeHeaderValue("JWT");

			// The inner JWT is the payload of the outer JWT
			jwe.setPayload(jws);
			
			logger.debug("JWS Payload ..." + jws);
		  
			// Produce the JWE compact serialization, which is the complete
			// JWT/JWE
			// representation,
			// which is a string consisting of five dot ('.') separated
			// base64url-encoded parts in the form
			// Header.EncryptedKey.IV.Ciphertext.AuthenticationTag

			jwt = jwe.getCompactSerialization();
			
			logger.info("JWE Serialized"); 			 

		} catch (Exception e1) {
			logger.error("Error Creating JWE: " + e1.getMessage(), e1);
			throw new WaveMoneyJWTException(500, "JW01", e1.getMessage(), e1);
		}
		
		if(jwt == null)
		{
			throw new WaveMoneyJWTException(500, "JW02", "Error creating JWE");
		} 
		
		return jwt;
	}

	String createJWT(JwtClaims claims, MuleEventContext eventContext) throws WaveMoneyJWTException {
		
		logger.info("*** Creating JWT ****"); 
		
		logger.debug("Mule Payload Class: " + eventContext.getMessage().getPayload().getClass().getName());
		logger.debug("Mule Payload Value: " + eventContext.getMessage().getPayloadForLogging());
		

		// Create the Claims, which will be the content of the JWT
		claims.setIssuer("WM"); // who creates the token and signs it
		claims.setAudience("WMT-MFS"); // to whom the token is intended to be
										// sent
		//CRM will not have an expiration time for the JWT
		//claims.setExpirationTimeMinutesInTheFuture(10); // time when the token
														// will expire (10
														// minutes from now)
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow(); // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(2); // time before which the token
												// is not yet valid (2 minutes
												// ago)
		claims.setSubject("WMT-MFS"); // the subject/principal is whom the token
										// is about

		//CRM will not have a NONCE set to its JWTID
		//String uuidJti = UUID.randomUUID().toString();
		//logger.info("uuidJti: " + uuidJti);
		//claims.setJwtId(uuidJti);

//		try {
//			logger.info("expirationTime: " + claims.getExpirationTime());
//			logger.info("expirationTime toString(): " + claims.getExpirationTime().toString());
//			logger.info("expirationTime getValueInMillis(): " + claims.getExpirationTime().getValueInMillis());
//			logger.info("expirationTime getValue(): " + claims.getExpirationTime().getValue());
//
//			DbUtil.insertNonce(uuidJti, claims.getExpirationTime().getValue());
//
//		} catch (MalformedClaimException e1) {
//			logger.error("Claim Exception: " + e1.getMessage(), e1);
//			throw new WaveMoneyJWTException(500, "JW03", e1.getMessage(), e1);
//		}

		// A JWT is a JWS and/or a JWE with JSON claims as the payload.
		// In this case it is a JWS so we create a JsonWebSignature object.

		JsonWebSignature jws = null;

		try {

			jws = new JsonWebSignature();
			
			logger.info("JsonWebSignature created "); 

		} catch (Exception e1) {
			logger.error("Error Creating JsonWebSignature Object. Message: " + e1.getMessage(), e1);
			throw new WaveMoneyJWTException(500, "JW04", e1.getMessage(), e1);
		}

		logger.info("JsonWebSignature object has been created");

		// The payload of the JWS is JSON content of the JWT Claims
		jws.setPayload(claims.toJson());

		logger.info("Clame has been converted to JSON");

		// The JWT is signed using the private key
		jws.setKey((RSAPrivateKey) getPrivateKey(publicKey, u.getProperty("jks.private.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.private.jwt.encrypt.alias", CRM_PROPERTIES)));

		// Set the Key ID (kid) header.
		// We only have one key.
		jws.setKeyIdHeaderValue("mfs");

		// Set the signature algorithm on the JWT/JWS that will integrity
		// protect the claims
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);

		// Sign the JWS and produce the compact serialization or the complete
		// JWT/JWS
		// representation, which is a string consisting of three dot ('.')
		// separated
		// base64url-encoded parts in the form Header.Payload.Signature
		String jwt = "";

		try {

			jwt = jws.getCompactSerialization();

			logger.info("JWT has been Serializated");

		} catch (Exception e1) {

			logger.error("Error Serializing JWT. Message: " + e1.getMessage(), e1);

			throw new WaveMoneyJWTException(500, "JW05", e1.getMessage(), e1);

		}
		
		if(jwt == null)
		{
			throw new WaveMoneyJWTException(500, "JW06", "Error creating JWT");
		}

		return jwt;

	}

	public JwtClaims validateJWEAndReturnClaims(String jwt) throws WaveMoneyJWTException {

		JwtClaims jwtClaims = null;
		
		logger.info("*** Validating JWE And Return Claims ***");

		try {
			
			AlgorithmConstraints jweAlgConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					KeyManagementAlgorithmIdentifiers.RSA1_5);

			AlgorithmConstraints jweEncConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			
			Util u = new Util();
			
			// Use JwtConsumerBuilder to construct an appropriate JwtConsumer,
			// which will
			// be used to validate and process the JWT.
			// The specific validation requirements for a JWT are context
			// dependent, however,
			// it typically advisable to require a (reasonable) expiration time,
			// a trusted issuer, and
			// and audience that identifies your system as the intended
			// recipient.
			//CRM will not verify the JWT has expiration time set
			//.setRequireExpirationTime() // the
			// JWT
			// must
			// have
			// an
			// expiration
			// time
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setAllowedClockSkewInSeconds(30) // allow some leeway in
														                                        // validating time based
														                                        // claims to account for
														                                        // clock skew
					.setRequireSubject() // the JWT must have a subject claim
					.setExpectedIssuer("WM") // whom the JWT needs to have been
												// issued by
					.setExpectedAudience("WMT-MFS") // to whom the JWT is
													// intended for
					.setDecryptionKey((RSAPrivateKey) getPrivateKey(publicKey, u.getProperty("jks.private.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.private.jwt.encrypt.alias", CRM_PROPERTIES))) // decrypt
																											// with
																											// the
																											// receiver's
																											// private
																											// key
					.setVerificationKey((RSAPublicKey) getPublicKey(publicKey, u.getProperty("jks.public.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.public.jwt.encrypt.alias", CRM_PROPERTIES))) // verify
																											// the
																											// signature
																											// with
																											// the
																											// public
																											// key
					.setJwsAlgorithmConstraints( // only allow the expected
													// signature algorithm(s) in
													// the given context
							new AlgorithmConstraints(ConstraintType.WHITELIST, // which
																				// is
																				// only
																				// RS512
																				// here
									AlgorithmIdentifiers.RSA_USING_SHA512))
					.setJweAlgorithmConstraints(jweAlgConstraints)
					.setJweContentEncryptionAlgorithmConstraints(jweEncConstraints).build(); // create
																								// the
																								// JwtConsumer
																								// instance

			logger.info("Jwt Consumer Builder Done");
			
			// Validate the JWT and process it to the Claims
			jwtClaims = jwtConsumer.processToClaims(jwt);
			
			logger.info("Jwt processed");
			
//			try {
//				DbUtil.deleteNonce(jwtClaims.getJwtId());
//				logger.info("Jwt: Nonce has been deleted");
//			} catch (MalformedClaimException e1) {
//				logger.error("Error deleting Nonce: " + e1.getMessage(), e1);
//				throw new WaveMoneyJWTException(500, "JW07", e1.getMessage(), e1);
//			}
			
			logger.info("JWE-JWS-JWT validation succeeded! " + jwtClaims);
			
			return jwtClaims;

		} catch (InvalidJwtException e) {
			// InvalidJwtException will be thrown, if the JWT failed processing
			// or validation in anyway.
			// Meaningful explanations(s) about what went wrong.
			logger.error("Invalid JWT! " + e.getMessage(), e);

			// Programmatic access to (some) specific reasons for JWT invalidity
			// is also possible
			// should you want different error handling behavior for certain
			// conditions.

			// Whether or not the JWT has expired being one common reason for
			// invalidity
			if (e.hasExpired()) {
				
				NumericDate expTime = null;
				try {
					
					expTime = e.getJwtContext().getJwtClaims().getExpirationTime();
					
					logger.error("JWT expired at " + expTime);
					
				} catch (MalformedClaimException e1) {
					logger.error("JWT Malformed Claim Exception JWT! " + e1.getMessage(),e1);
					throw new WaveMoneyJWTException(500, "JW08", e1.getMessage(), e1);
				}
				
				throw new WaveMoneyJWTException(400, "JW09", "JWT expired at " + expTime, e);
			}

			// Or maybe the audience was invalid
			if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
				
				
				List<String> tmpAudience = null;
				
				try {
					tmpAudience = e.getJwtContext().getJwtClaims().getAudience();
				} catch (MalformedClaimException e1) {
					logger.error("JWT Malformed Claim Exception JWT: " + e1.getMessage(),e1);
					throw new WaveMoneyJWTException(500, "JW10", e1.getMessage(), e1);
				}
				
				throw new WaveMoneyJWTException(400, "JW11", "JWT Audience Invalid " + tmpAudience.toString(), e);
			}
  
			throw new WaveMoneyJWTException(500, "JW12", e.getMessage(), e);
			
		}
		 
	}

	public JwtClaims validateJWE4FinOpsAndReturnClaims(String jwt) throws WaveMoneyJWTException {
		
		JwtClaims jwtClaims = null;
		
		logger.info("*** Validating JWE For Fin OPs And Return Claims ***");
		
		try {
			
			AlgorithmConstraints jweAlgConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					KeyManagementAlgorithmIdentifiers.RSA1_5);

			AlgorithmConstraints jweEncConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			
			// Use JwtConsumerBuilder to construct an appropriate JwtConsumer,
			// which will
			// be used to validate and process the JWT.
			// The specific validation requirements for a JWT are context
			// dependent, however,
			// it typically advisable to require a (reasonable) expiration time,
			// a trusted issuer, and
			// and audience that identifies your system as the intended
			// recipient.
			//CRM will not verify if JWT has expiration time configured
			//.setRequireExpirationTime() // the
			// JWT
			// must
			// have
			// an
			// expiration
			// time
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setAllowedClockSkewInSeconds(30) // allow some leeway in
														                                        // validating time based
														                                        // claims to account for
														                                        // clock skew
					.setRequireSubject() // the JWT must have a subject claim
					.setExpectedIssuer("WM") // whom the JWT needs to have been
												// issued by
					.setExpectedAudience("WMT-MFS") // to whom the JWT is
													// intended for
					.setDecryptionKey((RSAPrivateKey) getPrivateKey(publicKey, u.getProperty("jks.private.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.private.jwt.encrypt.alias", CRM_PROPERTIES))) // decrypt
																											// with
																											// the
																											// receiver's
																											// private
																											// key
					.setVerificationKey((RSAPublicKey) getPublicKey(publicKey, u.getProperty("jks.public.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.public.jwt.encrypt.alias", CRM_PROPERTIES))) // verify
																											// the
																											// signature
																											// with
																											// the
																											// public
																											// key
					.setJwsAlgorithmConstraints( // only allow the expected
													// signature algorithm(s) in
													// the given context
							new AlgorithmConstraints(ConstraintType.WHITELIST, // which
																				// is
																				// only
																				// RS512
																				// here
									AlgorithmIdentifiers.RSA_USING_SHA512))
					.setJweAlgorithmConstraints(jweAlgConstraints)
					.setJweContentEncryptionAlgorithmConstraints(jweEncConstraints).build(); // create
																								// the
																								// JwtConsumer
																								// instance

			
			logger.info("Jwe Consumer Builder Done");
			
			// Validate the JWT and process it to the Claims
			jwtClaims = jwtConsumer.processToClaims(jwt);
			
			logger.info("Jwe processed");

			try {
				
				if (true) {
					
					//logger.info("Jwe: Nonce has been deleted");
					
					logger.debug("JWE-JWS-JWT validation succeeded! " + jwtClaims);
					
					return jwtClaims;
					
				} else {
					
					logger.error("JWE Invalid Nonce");
					
					throw new WaveMoneyJWTException(500, "JW14", "JWE Invalid Nonce");
					 
				}
				
			} catch (Exception e1) {
				
				logger.error("JWE Malformed Claim Exception JWT!" + e1.getMessage(), e1);
				
				throw new WaveMoneyJWTException(500, "JW15", e1.getMessage(), e1);
				
			}

		} catch (InvalidJwtException e) {
			
			// InvalidJwtException will be thrown, if the JWT failed processing
			// or validation in anyway.
			// Meaningful explanations(s) about what went wrong.
			 
			logger.error("JWE Invalid JWT" + e.getMessage(), e);

			// Programmatic access to (some) specific reasons for JWT invalidity
			// is also possible
			// should you want different error handling behavior for certain
			// conditions.

			// Whether or not the JWT has expired being one common reason for
			// invalidity
			
			if (e.hasExpired()) {
				
				NumericDate expTime = null;
				
				try {
					
					expTime = e.getJwtContext().getJwtClaims().getExpirationTime();
					
					logger.error("JWE expired at " + expTime);
					
				} catch (MalformedClaimException e1) {
					
					logger.error("JWE Malformed Claim Exception JWT! " + e1.getMessage(),e1);
					
					throw new WaveMoneyJWTException(500, "JW16", e1.getMessage(), e1);
				}
				
				throw new WaveMoneyJWTException(400, "JW17", "JWE expired at " + expTime, e);
			}

			// Or maybe the audience was invalid
			if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) { 
				
				List<String> tmpAudience = null;
				
				try {
					tmpAudience = e.getJwtContext().getJwtClaims().getAudience();
				} catch (MalformedClaimException e1) {
					logger.error("JWE Malformed Claim Exception JWT: " + e1.getMessage(),e1);
					throw new WaveMoneyJWTException(500, "JW18", e1.getMessage(), e1);
				}
				
				throw new WaveMoneyJWTException(400, "JW19", "JWE Audience Invalid " + tmpAudience.toString(), e);
				
			}

			throw new WaveMoneyJWTException(500, "JW20", e.getMessage(), e);
		}
		  
	}

	public JwtClaims validateJWTAndReturnClaims(String jwt) throws WaveMoneyJWTException  {
		
		JwtClaims jwtClaims = null;
		
		logger.info("*** Validating JWT And Return Claims ***");
		
		try {
			// Use JwtConsumerBuilder to construct an appropriate JwtConsumer,
			// which will
			// be used to validate and process the JWT.
			// The specific validation requirements for a JWT are context
			// dependent, however,
			// it typically advisable to require a (reasonable) expiration time,
			// a trusted issuer, and
			// and audience that identifies your system as the intended
			// recipient.
			// CRM will not validate if expiration time has been set 
			//.setRequireExpirationTime() // the
			// JWT
			// must
			// have
			// an
			// expiration
			// time
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setAllowedClockSkewInSeconds(30) // allow some leeway in
														// validating time based
														// claims to account for
														// clock skew
					.setRequireSubject() // the JWT must have a subject claim
					.setExpectedIssuer("WM") // whom the JWT needs to have been
												// issued by
					.setExpectedAudience("WMT-MFS") // to whom the JWT is
													// intended for
					.setVerificationKey((RSAPublicKey) getPublicKey(publicKey, u.getProperty("jks.public.jwt.encrypt.password", CRM_SEC_PROPERTIES), u.getProperty("jks.public.jwt.encrypt.alias", CRM_PROPERTIES))) // verify
																											// the
																											// signature
																											// with
																											// the
																											// public
																											// key
					.setJwsAlgorithmConstraints( // only allow the expected
													// signature algorithm(s) in
													// the given context
							new AlgorithmConstraints(ConstraintType.WHITELIST, // which
																				// is
																				// only
																				// RS512
																				// here
									AlgorithmIdentifiers.RSA_USING_SHA512))
					.build(); // create the JwtConsumer instance

			logger.info("JWT Consumer Builder Done");
			
			// Validate the JWT and process it to the Claims
			jwtClaims = jwtConsumer.processToClaims(jwt);
			
			logger.debug("JWT validation succeeded! " + jwtClaims);
			
			return jwtClaims;
			
		} catch (InvalidJwtException e) {
			
			// InvalidJwtException will be thrown, if the JWT failed processing
			// or validation in anyway.
			// Meaningful explanations(s) about what went wrong.
			logger.error("Invalid JWT! " + e, e);

			// Programmatic access to (some) specific reasons for JWT invalidity
			// is also possible
			// should you want different error handling behavior for certain
			// conditions.

			// Whether or not the JWT has expired being one common reason for
			// invalidity
			
			if (e.hasExpired()) {
				
				NumericDate expTime = null;
				
				try {
					
					expTime = e.getJwtContext().getJwtClaims().getExpirationTime();
					
					logger.error("JWT expired at " + expTime);
					
				} catch (MalformedClaimException e1) {
						
					logger.error("JWT Malformed Claim Exception JWT! " + e1.getMessage(),e1);
					
					throw new WaveMoneyJWTException(500, "JW21", e1.getMessage(), e1);
				}
				
				throw new WaveMoneyJWTException(400, "JW22", "JWT expired at " + expTime, e);
				
			}

			// Or maybe the audience was invalid
			if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
				
				List<String> tmpAudience = null;
				
				try {
					
					logger.error("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
					
					tmpAudience = e.getJwtContext().getJwtClaims().getAudience();
					
				} catch (MalformedClaimException e1) {
					
					logger.error("JWT Malformed Claim Exception JWT: " + e1.getMessage(),e1);
					
					throw new WaveMoneyJWTException(500, "JW23", e1.getMessage(), e1);
				}
				
				throw new WaveMoneyJWTException(400, "JW24", "JWT Audience Invalid " + tmpAudience.toString(), e);
				
			}

			throw new WaveMoneyJWTException(500, "JW25", e.getMessage(), e);
			
		}
		
	}

	private static PrivateKey getPrivateKey(String filename, String password, String alias) throws WaveMoneyJWTException {
		
		
		PrivateKey privateKey = null;
		
		logger.info("--- Getting Private Key ---");
		 
		try {
			
			KeyStore keystore = KeyStore.getInstance("JKS");

			InputStream is = null;

			is = new FileInputStream(filename);

			keystore.load(is, password.toCharArray());
			
			logger.info("Private Key Loaded");

			privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
			
			logger.info("Private Key ready");
			
			
		} catch (FileNotFoundException e1) {

			logger.error("PK not found" + e1.getMessage(),e1);
			
			throw new WaveMoneyJWTException(500, "JW26", "Private Key not found" , e1);
			
		} catch (Exception e1) {
			
			logger.error("Error getting Private Key" + e1.getMessage(),e1);
			 
			throw new WaveMoneyJWTException(500, "JW27", "Error getting Private Key" , e1);
		}

		if (privateKey == null) {
			
			logger.error("Failed to retrieve private key from keystore");
			
			throw new WaveMoneyJWTException(500, "JW28", "Error getting PK");
			
		}
		
		logger.info("Private Key returned");

		return privateKey;
	}

	private static PublicKey getPublicKey(String filename, String password, String alias) throws WaveMoneyJWTException {
		
		Key key = null;
		
		PublicKey publicKey = null;
		
		logger.info("--- Getting Public Key ---");
		 
		try {
			
			KeyStore keystore = KeyStore.getInstance("JKS");

			InputStream is = null;

			is = new FileInputStream(filename);

			keystore.load(is, password.toCharArray());
			
			logger.info("Public Key Loaded");

			key = keystore.getKey(alias, password.toCharArray());

			if (key instanceof PrivateKey) {

				// Get certificate of public key
				Certificate cert = keystore.getCertificate(alias);

				// Get public key
				publicKey = cert.getPublicKey();
				
				logger.info("Public Key ready"); 
				 
			}
			else
			{
				logger.info("Invalid Public Key"); 
				
			}

		} catch (FileNotFoundException e1) {
					
			logger.error("Public Key not found" + e1.getMessage(),e1);
			
			throw new WaveMoneyJWTException(500, "JW11", "Public Key not found" , e1);
			
		} catch (Exception e1) {
			
			logger.error("Error getting Public Key" + e1.getMessage(),e1);
			 
			throw new WaveMoneyJWTException(500, "JW28", "Error getting Public Key" , e1);
		}

		if (publicKey == null) {
			
			logger.error("Failed to retrieve public key from keystore");
			
			throw new WaveMoneyJWTException(500, "JW29", "Failed to retrieve public key from keystore");
		}

		logger.info("Public Key returned");
		
		return publicKey;
	}

	private static KeyPair getKeyPair(String filename, String password, String alias) throws WaveMoneyJWTException {
		
		Key key = null;
		PublicKey publicKey = null;
		KeyPair keyPair = null;
		
		logger.info("--- Getting Key Pair ---");

		try { 
			
			KeyStore keystore = KeyStore.getInstance("JKS");

			InputStream is = null;

			is = new FileInputStream(filename);

			keystore.load(is, password.toCharArray());
			
			logger.info("Pair Key Loaded");

			key = keystore.getKey(alias, password.toCharArray());

			if (key instanceof PrivateKey) {

				// Get certificate of public key
				Certificate cert = keystore.getCertificate(alias);

				// Get public key
				publicKey = cert.getPublicKey();
				
				logger.info("Pair Key ready"); 

				// Return a key pair
				
				keyPair = new KeyPair(publicKey, (PrivateKey) key);

			}
			else
			{
				logger.info("Invalid Pair Key"); 
			}

		} catch (FileNotFoundException e1) {
			
			logger.error("Pair Key not found" + e1.getMessage(),e1);
			
			throw new WaveMoneyJWTException(500, "JW30", "Pair Key not found" , e1);
			
		} catch (Exception e) {
			
				logger.error("Failed to retrieve pair key from keystore");
			
				throw new WaveMoneyJWTException(500, "JW31", "Failed to retrieve pair key from keystore");
		}

		if (keyPair == null) {
			
			logger.error("Failed to retrieve pair key from keystore");
			
			throw new WaveMoneyJWTException(500, "JW32", "Failed to retrieve pair key from keystore");
		}

		return keyPair;
	}

}
