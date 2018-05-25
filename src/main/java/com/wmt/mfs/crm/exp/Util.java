package com.wmt.mfs.agent.exp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Util {
	
	public String getProperty(String propertyLabel, String propertiesFile) throws RuntimeException {

		String propertyValue = null;

		Properties prop = new Properties();

//		InputStream input = Util.class.getResourceAsStream(propertiesFile);
		
		InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream(propertiesFile);

//		InputStream input = ClassLoader.getSystemClassLoader().getResourceAsStream(propertiesFile);
		
		if (input != null) {

			try {

				prop.load(input);

				propertyValue = prop.getProperty(propertyLabel);

			} catch (IOException e) {

				throw new RuntimeException(e.getMessage(), e);

			} finally {

				if (input != null) {

					try {
						input.close();
					} catch (IOException e) {
						e.printStackTrace();
					}

				}
			}

		} else {
			throw new RuntimeException("Missing " + propertiesFile + " file");
		}
		return propertyValue;
	}

}
