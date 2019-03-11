
package com.mtcap.v1.verifiedtoken.customerdecoder;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

/**
 * <p>
 * Sample java code to Decrypt and Check MTCaptcha Verified Token
 * </p>
 * 
 * <p>
 * license		https://www.apache.org/licenses/LICENSE-2.0  <br>
 * copyright	MTCatpcha 2019 <br>
 * </p>
 * 
 * <p>
 * - Decode the MTCaptcha VerifiedToken (v1) locally using the PrivateKey, without making an API call <br >
 * - Check if the token info is valid.  <br >
 * </p>
 * 
 * <hr> 
 * <pre>
 * 
 * Example use: 
 * 
 *   MTCaptchaTokenDecoderAndChecker decoder	= new MTCaptchaTokenDecoderAndChecker();
 *   MTCaptchaTokenDecoderAndChecker.DecodedMTTokenInfo di	= null;
 * 
 *   boolean  isSuccess = false;
 * 
 *   String[] expectedDomains = {"some.example.com", "another.example.com"};
 *   String   expectionAction = "login";
 *   Boolean  isProductionEnv = true;    
 * 
 *   <font color="blue">
 *   di = decoder.decodeMTToken(privatekey, token);
 * 
 *   if( di.decodeSuccess)
 *   {
 *     decoder.checkMTTokenSuccess(di, expectedDomains, expectionAction, isProductionEnv);
 *     isSuccess = di.checkSuccess;
 *   }
 *   </font>
 * 
 * </pre>
 * <hr> 
 * 
 * <p>
 * <b>NOTE / WARNING:</b> <br >
 * Method <b>{@link #checkTokenGUIDIsNotUsedAndMark(String, Long) checkTokenGUIDIsNotUsedAndMark()}</b> 
 * is really for demonstration purpose and should be over written. The current impl is an acceptable single 
 * server implementation, using local memory to track if a particular token (GUID) has been used before. For 
 * applications where there are more than 1 (single) server instance, this should be replaced by 
 * some check via shared cache (with expiration) such as MemCached / REDIS etc. 
 * </p>
 * 
 * <p>
 * The class is Thread Safe
 * </p>
 * 
 * <p>
 * This code is for demonstration purpose and licensed 
 * under APACHE LICENSE 2.0
 * </p>
 * 
 * <hr >
 * <br>
 * <b>Verified Token Format Overview</b>
 * 
 * <pre>
 * 
 *  Sample Verified-Token
 *  v1(2f03cc7d,1058dfde,MTPublic-hal9000uJ,34715559cd42d3955114303c925c3582,kSdkIYABYAKSmXze77v8oC1zCpBQJAOeCNaD8Q9ZnHTl3XTJ49KNll-FR3T-yzqE23CncDtF1o6IiyoCPEAeVnWshzllM0TqppHtp7KzGMJiUEApltXGHYlK6V2EasR-pNCaJo99k0W8tm5OR2kt5xefFH-cYypRRzIWzoppZMSntamR6SVYCotqfwKJ8OMb9WkYpoBV3e7_sjDUe-3_b_t55Sdf5CqmBkZWNkV0nbKdP9fngrmaDD3yJLkuUbKRBFySB7KHCgFgzVpzEQndCK0NcbFuuGbxbzYXmoxo8nKQsPVJB7s-vBu1Z5ZfD400bRfUTGoj8BH6w4RQD5qOCQ**)
 * 
 *  VerifiedToken Structure
 *  "v1("  [MTCaptcha CheckSum]  "," [Customer Checksum] "," [Sitekey] "," [Random Seed] "," [Encrypted TokenInfo] ")"
 * 
 *  Sample TokenInfo Decrypted (JSON)
 *  {
 *    "v":"1.0",
 *    "code":201,
 *    "codeDesc":"valid:captcha-solved",
 *    "tokID":"34715559cd42d3955114303c925c3582",
 *    "timestampSec":981173106,
 *    "timestampISO":"2001-02-03T04:05:06Z",
 *    "hostname":"some.example.com",
 *    "isDevHost":false,
 *    "action":"",
 *    "ip":"10.10.10.10"
 *  }
 *
 * </pre>
 * 
 * <p>
 * DEPENDENCIES  <br>
 * - Google GSON 2.8.2+  <br>
 * - Apache Common Codec  1.11+  <br>
 * - Java 8  <br>
 * </p>
 * 
 * @author		batou@mtcatpcha.com
 * @version		2019-MAR-10
 * 
 */
public class MTCaptchaTokenDecoderAndChecker
{

	/**The Token's max allowed age in seconds */
	private final long	TokenMaxAgeSeconds			= 60L * 5L;		// 5 minutes;

	/**Some padding in case of differences in local server clock and MTCaptcha server clock */
	private final long	ClockDriftPaddingSeconds	= 20L;			// 20 seconds, 
	
	
	
	/**The GSON used to transform JSON string to Pojo object*/
	private final Gson	gson;
			
	public MTCaptchaTokenDecoderAndChecker()
	{
        GsonBuilder gsonBuilder = new GsonBuilder(); 
        gsonBuilder.setLenient(); 
        gsonBuilder.serializeNulls();
        gson = gsonBuilder.create();
	}
	
	/**
	 * Checks if the DecodedMTTokenInfo is valid. 
	 * 
	 * @param di			   The DecodedMTTokenInfo object, result from original decode call
	 * @param expectedDomains  The array of acceptable domains to check with
	 * @param exepctedAction   The expected action, can be null if not set
	 * @param isProductionEnv  Checks if token is generated under a Production or Development domain (configured by Sitekey)
	 * 
	 * The di.checkSuccess		will be updated to true/false depending on the results of this check
	 * The di.checkFailMsg		will be updated if di.succcess==false
	 * 
	 * is Thread Safe
	 * 
	 * @return true, if the token is valid
	 * 
	 */
	public boolean checkMTTokenSuccess(DecodedMTTokenInfo di, String[] expectedDomains, String exepctedAction, Boolean isProductionEnv)
	{
		
		if(di == null)
			throw new IllegalArgumentException("argument di is null");

		
		di.checkSuccess		= false;

		// CHECK IF THERE WAS ANY ERRORs DURING DECODING/DECRYPTION
		if(di.decodeErrorMsg != null)
		{
			di.checkFailMsg	= "TokenInfo.FailedDecode";
			return false;
		}		
		
		// CHECK TOKEN POJO IS NOT NULL
		if(di.tokenInfoPojo == null)
		{
			di.checkFailMsg	= "TokenInfo.NotFound";
			return false;
		}


		

		
		// CHECK IF TOKEN IS NOT TOO OLD
		long maxAgeSeconds		= TokenMaxAgeSeconds;		
		long nowSeconds			= System.currentTimeMillis() / 1000L;		
		long timeBoundLower		= nowSeconds - maxAgeSeconds;
		long timeBoundUpper		= nowSeconds + ClockDriftPaddingSeconds;
		
		if(di.tokenInfoPojo.timestampSec  < timeBoundLower || 
			di.tokenInfoPojo.timestampSec > timeBoundUpper)
		{
			di.checkFailMsg	= "TokenTime.Expired";
			return false;
		}
		
		
		// CHECK IF THE TOKEN WAS USED (CHECKED) BEFORE
		if(! checkTokenGUIDIsNotUsedAndMark(di.tokenInfoPojo.tokID, di.tokenInfoPojo.timestampSec))
		{
			di.checkFailMsg	= "Token.DuplicateUse";
			return false;
		}
				
		
		// CHECK IF THE DOMAIN IS EXPECTED
		if(expectedDomains != null )
		{
			boolean domainValid = false;
			for(String domain: expectedDomains)
			{
				if(domain.equalsIgnoreCase(di.tokenInfoPojo.hostname))
				{
					domainValid = true;
					break;
				}
			}
			
			if(! domainValid)
			{
				di.checkFailMsg	= "Hostname.NotMatch";
				return false;
			}
		}
		
		// CHECK IF THE ACTION IS EXPECTED
		if(exepctedAction != null)
		{
			if( ! exepctedAction.equalsIgnoreCase(di.tokenInfoPojo.action) )
			{
				di.checkFailMsg	= "Action.NotMatch";
				return false;
			}
		
		}
		
		// CHECK IF OF EXPECTED PRODUCTION ENV
		if(isProductionEnv != null)
		{
			if( isProductionEnv.equals( di.tokenInfoPojo.isDevHost ) )
			{
				di.checkFailMsg	= "Env.NotMatch";
				return false;
			}
		}


		
		di.checkSuccess = true;
		return di.checkSuccess;
	}
	
	
	
	//---------------- CheckTokenGUIDIsNotUsedAndMark START-------------------------------------//
	//------ FOR MULTI SERVER ENVIRONEMNTS, REPLACE BELOW WITH SHARED CACHE IMPLEMENTATION -----//
	
	private ReentrantLock	  tokenKeyRegistryGCLock		= new ReentrantLock();					
	private AtomicInteger	  tokenKeyRegistryGCAddCounter	= new AtomicInteger();  
	private ConcurrentHashMap<String, Long> tokenKeyRegistry = new ConcurrentHashMap(1000);
	
	public boolean checkTokenGUIDIsNotUsedAndMark(String guid, Long tokenCreateTimeSec)
	{

System.out.println("WARN! FOR MULTISERVER ENVS, NEED TO REPLACE THIS CODE: "+this.getClass().getName()+".checkTokenGUIDIsNotUsedAndMark() ");
System.out.println("WARN! FOR MULTISERVER ENVS, NEED TO REPLACE THIS CODE: "+this.getClass().getName()+".checkTokenGUIDIsNotUsedAndMark() ");
		
		boolean isUsed = false;
		
		
		// ATOMICALLY CHECK IF THE GUID IS USED/MARKED ALREADY
		Object prev = tokenKeyRegistry.putIfAbsent(guid, tokenCreateTimeSec);
		if(prev == null ){
			isUsed = false;
		}
		else{
			isUsed = true;
		}

		
		// REMOVE ANY RECORDED TOKEN THAT HAVE EXPIRED 
		if(! isUsed )
		{
			int count = tokenKeyRegistryGCAddCounter.incrementAndGet();
			if(count >= 200)	// do this every 200 adds
			{
				if(tokenKeyRegistryGCLock.tryLock())
				{
					tokenKeyRegistryGCAddCounter.set(0);

					long nowSeconds				= System.currentTimeMillis() / 1000L;
					long expireThresholdTime	= nowSeconds - TokenMaxAgeSeconds;

					try{

						for(Map.Entry<String, Long> entry : tokenKeyRegistry.entrySet() )
						{
							if(entry.getValue() < expireThresholdTime)
								tokenKeyRegistry.remove(entry.getKey());
						}

					}finally{
						tokenKeyRegistryGCLock.unlock();
					}
				}
			}
		}
		
		return ! isUsed;
		
	}

	//---------------- CheckTokenGUIDIsNotUsedAndMark END-------------------------------------//
	//----------------------------------------------------------------------------------------//	
	
	
	
	/**
	 * Decodes and Decrypts the MTCaptcha VerifiedToken
	 * 
	 * @param privatekey The privatekey 
	 * @param token		 The verified token string
	 * 
	 * @return DecodedMTTokenInfo
	 *   decodedMTTokenInfo.decodeSuccess	will be set true/false depending on success or failure of decode
	 *	 decodedMTTokenInfo.decodeErrorMsg  will be set with message if DecodedMTTokenInfo.decodeSuccess = false;
	 * 
	 */
	public DecodedMTTokenInfo decodeMTToken(String privatekey, String token)
	{	
		
	   if(token == null)
		   throw new IllegalArgumentException("argument token is null");
	   if(privatekey == null)
		   throw new IllegalArgumentException("argument privatekey is null");


	   DecodedMTTokenInfo di = new DecodedMTTokenInfo();

	   
	   TRY_DECODE:
	   try{ 

		   di.init(privatekey, token);

		   // UNPACK THE TOKEN INTO COMPONENTS
		   if( ! unpackToken(di) )
			   break TRY_DECODE;
		   
		   // VALIDATE CHECKSUM MATCHES (NOT TAMPERED)
		   if( ! validateCustomerChecksum(di))
			   break TRY_DECODE;

		   // DECRYPT TOKEN 
		   if( ! decryptToken(di))
			   break TRY_DECODE;	   
		   
		   di.checkSuccess = false;
		   di.decodeSuccess = true;
		   
	   }catch(Exception e)
	   {
		   di.decodeErrorMsg = e.getClass()+":"+ e.getMessage();
	   }

	   return di;
	}

	
	
	protected boolean decryptToken(DecodedMTTokenInfo di)
	{
		
		byte[]			decryptedbytes;
		
		try{
		
			// REPLACE '*' with '=' character
			String			tokenInfoBase64Encrypted =  di.tokenInfoEncrypted;
							tokenInfoBase64Encrypted = tokenInfoBase64Encrypted.replace('*', '=');
							
			
			// DECODE URLSAFE BASE64 String to byte array
			byte[]			encryptedbytes	= Base64.getUrlDecoder().decode( tokenInfoBase64Encrypted );
			
			// GET SINGLE USE DECRYPTION KEY BYTES, WHICH IS GENERATED AS A HASH FROM PRIVATEKEY AND TOKEN RANDOM
			byte[]			decryptionKeyBytes	= getOneTimeEncryptionKey(di.privatekey, di.randomSeed);

			// CREATE IV (Initializing Vector) for decryption
			IvParameterSpec	ivParameterSpec = new IvParameterSpec(decryptionKeyBytes);
			SecretKeySpec	secretKeySpec	= new SecretKeySpec(decryptionKeyBytes, "AES");

			// USE ENCRYPTION ALOG AES with CBC and Padding
			Cipher			cipher			= Cipher.getInstance("AES/CBC/PKCS5Padding");

			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

			// DECRYPT THE DATA BYTES
			decryptedbytes	= cipher.doFinal(encryptedbytes);
			
			// CONVERT DECRYPTED BYTES TO JSON STRING USING UTF8 ENCODING
			String infoJson	=  new String(decryptedbytes, StandardCharsets.UTF_8);
			di.tokenInfoJson= infoJson;
			
			// PARSE JSON STRING TO POJO 
			MTTokenInfoPojo infoObj = (MTTokenInfoPojo)gson.fromJson(infoJson, MTTokenInfoPojo.class);
			di.tokenInfoPojo	= infoObj;
			
			return true;
		
		}catch(Exception e)
		{
			di.decodeErrorMsg = e.getClass()+":"+ e.getMessage();
			return false;
		}
		
		
	}
	
	/**
	 * Generate 128bit / 16byte key for decryption, 
	 * As a MD5 Has of the privatekey string and the token's randomseed string
	 * 
	 * @param privatekey	The privatekey
	 * @param randomSeed	The randomseed string from the token
	 * 
	 * @return The binary 128bit decryption key
	 * 
	 */
	protected byte[] getOneTimeEncryptionKey(String privatekey, String randomSeed)throws NoSuchAlgorithmException
	{
		
		// DecryptionKey = MD5( privatekey + randomSeed  ) 
		// (using UTF8 to convert String to input bytes for MD5); 
		// Thus DecrypteKey is thus 128 bits.
		
		MessageDigest	md5			= MessageDigest.getInstance("MD5");
		
						md5.update(	privatekey.getBytes(StandardCharsets.UTF_8)	);
						md5.update( randomSeed.getBytes(StandardCharsets.UTF_8)	);
						
		byte[]			oneTimeKey	= md5.digest();
		return			oneTimeKey;
		
	}	
	
	/**
	 * Validate the checksum matches and the token is not tampered
	 */
	protected boolean  validateCustomerChecksum(DecodedMTTokenInfo di)
	{
		
		// Convert all token text components to bytes using UTF8 encoding
		// CustomerCheckSum = MD5( privatekey + siteKey + randomSeed + tokenInfoEncrypted ) .lowercaseHex() .substring(0,8) 
		
		
		byte[] privatekeyBytes	= di.privatekey.getBytes(StandardCharsets.UTF_8);
		byte[] sitekeyBytes		= di.siteKey.getBytes(StandardCharsets.UTF_8);
		byte[] randomBytes		= di.randomSeed.getBytes(StandardCharsets.UTF_8);
		byte[] encinfoBytes		= di.tokenInfoEncrypted.getBytes(StandardCharsets.UTF_8);
		
		try{
	
			MessageDigest md5 = MessageDigest.getInstance("MD5");

			md5.update(privatekeyBytes);
			md5.update(sitekeyBytes);
			md5.update(randomBytes);
			md5.update(encinfoBytes);

			byte[]	md5bytes		= md5.digest();
			String	md5hex			= Hex.encodeHexString(md5bytes);

			String  calcChecksum	= md5hex.substring(0, 8);

			if(!calcChecksum.equals(di.customerChecksum))
			{
				di.decodeErrorMsg = "MalformedToken.CustomerChecksum";
				return false;
			}

			return true;
			
		}catch(NoSuchAlgorithmException e)
		{
			di.decodeErrorMsg = "MD5DigestNotFound";
			return false;
		}
	}
	
	/**
	* Parse and unpack the token into its components
	*/
	protected boolean unpackToken(DecodedMTTokenInfo di)
	{
		if(di.token.length() == 0)
		{
			di.decodeErrorMsg = "EmptyToken";
			return false;
		}

		// Check token length within allowed range
		if( (di.token.length() < "v1(xxxxxxxx,yyyyyyyy,MTPublic-zzzzzzzzz,rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr,iiiii)".length()) || 
			(di.token.length() > 1200) )
		{
		   di.decodeErrorMsg = "MalformedToken.TokenLength";
		   return false;
		}

		// check token envelope
		if( ! ( di.token.startsWith("v1(") && di.token.endsWith(")")  ) )
		{
		   di.decodeErrorMsg = "MalformedToken.Envelope";
		   return false;
		}			 


		//remove envelop 'v1(' and ')'
		String	noEnvelopToken	= di.token;
			   noEnvelopToken	= noEnvelopToken.substring(3, noEnvelopToken.length()-1);


	   String[] tokenParts		= noEnvelopToken.split("\\,");

	   // check if the token is broken into exactly 5 parts by comma ','
	   if(tokenParts.length != 5)
	   {
		   di.decodeErrorMsg = "MalformedToken.5Parts";
		   return false;
	   }

	   di.mtChecksum			= tokenParts[0];
	   di.customerChecksum		= tokenParts[1];
	   di.siteKey				= tokenParts[2];
	   di.randomSeed			= tokenParts[3];
	   di.tokenInfoEncrypted	= tokenParts[4];

	   if(di.mtChecksum.length() != 8)
	   {
		   di.decodeErrorMsg = "MalformedToken.MTCheckSumLength";
		   return false;
	   }		

	   if(di.customerChecksum.length() != 8)
	   {
		   di.decodeErrorMsg = "MalformedToken.CustomerCheckSumLength";
		   return false;
	   }

	   if(di.randomSeed.length() != 32)
	   {
		   di.decodeErrorMsg = "MalformedToken.RandomSeedLength";
		   return false;
	   }		

	   if(di.siteKey.length() < 16)
	   {
		   di.decodeErrorMsg = "MalformedToken.SiteKeyLength";
		   return false;
	   }	

	   if(di.tokenInfoEncrypted.length() < 6)
	   {
		   di.decodeErrorMsg = "MalformedToken.EncryptedInfoLength";
		   return false;
	   }			

	   return true;

	}

	//////////////////////////////////////////// 
	 
	/**
	 * Class that holds the different state and components during decryption and checking
	 */
	public static class DecodedMTTokenInfo
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
		String decodeErrorMsg		= null;
		
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
	
	/**
	 * Class that maps to the JSON TokenInfo
	 */
	public static class MTTokenInfoPojo
	{
		public MTTokenInfoPojo()
		{}
		
		public String	v;
		public Integer	code;
		public String	codeDesc;
		public String	tokID;
		public Long		timestampSec;
		public String	timestampISO;
		public String	hostname;
		public Boolean	isDevHost;
		public String	action;
		public String	ip;
		
	}
	
	
	///////////////////////////////////////////////
	///////////////////////////////////////////////
	
	
	/** Sample Running the code */
	public static void main(String[] args)
	{
		runDemo();
	}
	
	public static void runDemo()
	{
		
		String token	= "v1(2f03cc7d,1058dfde,MTPublic-hal9000uJ,34715559cd42d3955114303c925c3582,kSdkIYABYAKSmXze77v8oC1zCpBQJAOeCNaD8Q9ZnHTl3XTJ49KNll-FR3T-yzqE23CncDtF1o6IiyoCPEAeVnWshzllM0TqppHtp7KzGMJiUEApltXGHYlK6V2EasR-pNCaJo99k0W8tm5OR2kt5xefFH-cYypRRzIWzoppZMSntamR6SVYCotqfwKJ8OMb9WkYpoBV3e7_sjDUe-3_b_t55Sdf5CqmBkZWNkV0nbKdP9fngrmaDD3yJLkuUbKRBFySB7KHCgFgzVpzEQndCK0NcbFuuGbxbzYXmoxo8nKQsPVJB7s-vBu1Z5ZfD400bRfUTGoj8BH6w4RQD5qOCQ**)";
		//token			= "v1(6f270109,f0fbd331,MTPublic-hal9000uJ,542de54b4ff00b5c3148802e10eeed4b,A_v_IaSJYRsQxnQ8YC_LBqjLxxBzAG9twcjR3aRgfT3lTXUboq-r2CnuAkE6LPT6nrGB9tT2mS7WRWUAei0I18JerMdEFHcLLsCwfA1Ngef1AQQjqRWS8bl9rAb4RBk_6394PcTmKY8zb8RwCpU0dzRJkcy_AAdniEiNAotlI2qhyym8w35Io2gs10Kmt8ij30YaEuATOb18HC5jafr0UtVVBmzNNVYRdG9rwEf-LQuz_VEiYiYDCe1bEA4iruDcy_VyHi0zykBiXgaHFs5hL8Wt3FyZwC6JbQjnXenM7T3TiuHHCwzOVdnPS5JhCmu62bJKzOerXL6T1P6-PqswrA**)";

		
		String privatekey	= "hal9000uJ-WsPXwe3BatWpGZaEbja2mcO5r7h1h1PkFW2fRoyGRrp4ZH6yfq";
		String sitekey		= "MTPublic-hal9000uJ";
		
		
		MTCaptchaTokenDecoderAndChecker decoder = new MTCaptchaTokenDecoderAndChecker();
		
		//-----------DECODE THE TOKEN--------------//

		DecodedMTTokenInfo di = decoder.decodeMTToken(privatekey, token);
	
		
			System.out.println("DecodeError:  \t"+di.decodeErrorMsg);
			System.out.println("TokenInfoJson:\t"+di.tokenInfoJson);
			System.out.println("TokenInfoPojo:\t"+decoder.gson.toJson(di.tokenInfoPojo));		

			System.out.println();
		
		
		//------------CHECK THE TOKEN-------------//
			
			
			String[] expectedDomains = {"another.example.com", "some.example.com", "more.example.com"};
			String   expectedAction	 = "";
			Boolean	 isProductionEnv = true;
		 
		decoder.checkMTTokenSuccess(di, expectedDomains, expectedAction, isProductionEnv);
		
			System.out.println("CheckFailMsg:\t"+di.checkFailMsg);
			System.out.println("CheckSuccess:\t"+di.checkSuccess);

			decoder.checkMTTokenSuccess(di, expectedDomains, expectedAction, isProductionEnv);

			System.out.println("CheckFailMsg:\t"+di.checkFailMsg);
			System.out.println("CheckSuccess:\t"+di.checkSuccess);		
		
	}
	
}
