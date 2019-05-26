/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mtcap.v1.verifiedtoken.customerdecoder;

/**
 * Class that maps to the JSON TokenInfo
 */
public class MTTokenInfoPojo
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
