package com.mysmartlogon.gidsAppletTests;

import static org.junit.Assert.*;

import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.xml.bind.DatatypeConverter;

import org.junit.Before;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.mysmartlogon.gidsApplet.GidsApplet;

import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public abstract class GidsBaseTestClass {

	
	protected JavaxSmartCardInterface  simulator;
	private boolean display = true;
	
	@Before
	public void setUp() throws Exception {
		// 1. Create simulator
		byte[] TEST_APPLET_AID_BYTES = new byte[] {(byte) 0xA0,0x00,0x00,0x03,(byte) 0x97,0x42,0x54,0x46,0x59};
		AID TEST_APPLET_AID = new AID(TEST_APPLET_AID_BYTES, (short)0, (byte) TEST_APPLET_AID_BYTES.length);

		
		
		simulator = new JavaxSmartCardInterface ();

		// 2. Install applet
		simulator.installApplet(TEST_APPLET_AID, GidsApplet.class);
		simulator.selectApplet(TEST_APPLET_AID);
		// 3. Select applet
	}

	protected void createcard() {
		//display = false;
		execute("00A4040409A0000003974254465900");

		execute("00240180083132333435363738");

		execute("00E000000E620C82013983022F018C03032000");
		execute("0044000000");
		execute("00DB2F01034301F4");
		execute("00DB2F010547030801CC");
		execute("00DB2F010A46080102030405060708");
		
		execute("00E000000E620C8201398302A0008C03033000");
		execute("0044000000");
		execute("00E000000E620C8201398302A0108C03033000");
		execute("0044000000");
		execute("00E000000E620C8201398302A0118C030330FF");
		execute("0044000000");
		execute("00E000000E620C8201398302A0128C03032000");
		execute("0044000000");
		execute("00E000000E620C8201398302A0138C03033030");
		execute("0044000000");
		execute("00E000000E620C8201398302A0148C03032020");
		execute("0044000000");
		// create admin key
		execute("00 E0 00 00 1C 62 1A 82 01 18 83 02 B0 80 8C 04 87 00 20 FF A5 0B A4 09 80 01 02 83 01 80 95 01 C0");
		execute("0044000000");
		// set admin key
		execute("00DB3FFF267024840180A51F87180102030405060708010203040506070801020304050607088803B073DC");
		// set masterfile
		execute("00DBA00091DF1F818D016d736370000000000000000000000000000000000000000000a00000000000000000000000636172646964000000000020df000012a00000000000000000000000636172646170707300000021df000010a00000000000000000000000636172646366000000000022df000010a000006d7363700000000000636d617066696c6500000023df000010a00000");
		execute("00 DB A0 10 0B DF 21 08 6d 73 63 70 00 00 00 00");
		execute("00 DB A0 10 09 DF 22 06 00 00 00 00 00 00");
		execute("00 DB A0 10 03 DF 23 00");
		execute("00 DB A0 10 13 DF 20 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
		
		// activate
		execute("00 A4 00 0C 02 3F FF", false);
		execute("00 44 00 00 00", false);
		display = true;
	}

	protected void authenticateGeneral() {
		byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
		authenticateGeneral(key, true);
	}
	
	protected void authenticateMutual() {
		byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
		authenticateMutual(key, true);
	}
	
	protected void authenticatePin() {
		execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
	}
	protected void deauthenticate() {
		execute("00 20 00 82 00");
	}
	
	protected void authenticateMutual(byte[] key, boolean successexpected) {
		byte[] myChallenge= new byte [16], globalchallenge = new byte[40], challengeresponse = new byte[40];
		byte[] challenge;
		Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
    	DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
    	deskey.setKey(key, (short) 0);
		RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    	randomData.generateData(myChallenge, (short) 0, (short) myChallenge.length);
    	// select admin key
        execute("00 22 81 A4 03 83 01 80");
        // get a challenge
        ResponseAPDU response = execute("00 87 00 00 14 7C 12 81 10" + DatatypeConverter.printHexBinary(myChallenge) + "00");
        if (!Arrays.equals(Arrays.copyOfRange(response.getBytes(), 0, 4), new byte[] {0x7C,0x12,(byte) 0x81,0x10})) {
        	fail("not a challenge:" + DatatypeConverter.printHexBinary(response.getBytes()));
        }
        // compute the response
        challenge = Arrays.copyOfRange(response.getBytes(), 4, 20);
        //solve challenge
        //R2
        System.arraycopy(challenge, 0, globalchallenge, 0, 16);
        //R1
        System.arraycopy(myChallenge, 0, globalchallenge, 16, 16);
        // keep Z1 random
        
        cipherDES.init(deskey, Cipher.MODE_ENCRYPT);
        cipherDES.doFinal(globalchallenge, (short) 0, (short)40, challengeresponse, (short) 0);
        // send the response
        execute("00 87 00 00 2C 7C 2A 82 28" + DatatypeConverter.printHexBinary(challengeresponse), (successexpected?0x9000: 0x6982));
	}
	
	protected void authenticateGeneral(byte[] key, boolean successexpected) {
		byte[] challenge, challengeresponse = new byte[8];
		Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
    	DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
    	deskey.setKey(key, (short) 0);     

    	// select admin key
        execute("00 22 81 A4 03 83 01 80");
        // get a challenge
        ResponseAPDU response = execute("00 87 00 00 04 7C 02 81 00 00");
        if (!Arrays.equals(Arrays.copyOfRange(response.getBytes(), 0, 4), new byte[] {0x7C,0x0A,(byte) 0x81,0x08})) {
        	fail("not a challenge:" + DatatypeConverter.printHexBinary(response.getBytes()));
        }
        // compute the response
        challenge = Arrays.copyOfRange(response.getBytes(), 4, 12);
        //solve challenge
        cipherDES.init(deskey, Cipher.MODE_ENCRYPT);
        cipherDES.doFinal(challenge, (short) 0, (short)8, challengeresponse, (short) 0);
        // send the response
        execute("00 87 00 00 0C 7C 0A 82 08" + DatatypeConverter.printHexBinary(challengeresponse), (successexpected?0x9000: 0x6982)); 
	}
	
	protected void execute(String command, String expectedresponse) {
		byte[] expected = DatatypeConverter.parseHexBinary(expectedresponse.replaceAll("\\s",""));
		ResponseAPDU response = execute(command, 0xFFFF & Util.makeShort(expected[expected.length-2],expected[expected.length-1]));
		if (!Arrays.equals(response.getBytes(), expected)) {
			fail("expected: " + expectedresponse.replaceAll("\\s","") + " but was: " + DatatypeConverter.printHexBinary(response.getBytes()));
		}
		
	}
	
	protected ResponseAPDU execute(String Command) {
		return execute(Command,0x9000);
	}
	
	protected ResponseAPDU execute(String Command, int expectedReturn) {
		ResponseAPDU response = execute(Command,display);
		if(response.getSW() != expectedReturn) {
			fail("expected: " + Integer.toHexString(expectedReturn) + " but was: " + Integer.toHexString(response.getSW()));
		}
		return response;
	}
	
	

	private ResponseAPDU execute(String Command, boolean display) {
		
		Command = Command.replaceAll("\\s","");
		if (display) System.out.println(Command); 
		ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(DatatypeConverter.parseHexBinary(Command)));
		if (display) System.out.println(DatatypeConverter.printHexBinary(response.getBytes()));
		return response;
	}
}
