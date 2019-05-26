package com.mtcap.v1.verifiedtoken.customerdecoder;

/**
 * Class that holds the different state and components during decryption and checking
 */
public class DecodedMTTokenInfo
{
	// INPUT
	transient String  privatekey = null;
	String token				 = null;

	// DECODE INTERMEDIATE 
	String mtChecksum			= null;
	String customerChecksum		= null;
	String siteKey				= null;
	String randomSeed			= null;
	String tokenInfoEncrypted	= null;

	boolean decodeSuccess		= false;
	String  decodeErrorMsg		= null;

	// DECODE RESULT
	String			tokenInfoJson	= null;
	MTTokenInfoPojo	tokenInfoPojo	= null;

	// CHECK RESULT
	boolean			checkSuccess	= false;	
	String			checkFailMsg	= null;

	protected DecodedMTTokenInfo()
	{}

	protected void init(String privatekey, String token)
	{
		this.token		= token;
		this.privatekey	= privatekey;
		this.checkSuccess	= false;
	}
}	 
	