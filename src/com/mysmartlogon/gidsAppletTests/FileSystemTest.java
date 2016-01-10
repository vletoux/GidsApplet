package com.mysmartlogon.gidsAppletTests;

import javax.xml.bind.DatatypeConverter;

import org.junit.Before;
import org.junit.Test;

public class FileSystemTest extends GidsBaseTestClass {

	@Before
	public void setUp() throws Exception {
		super.setUp();
		createcard();
	}

	@Test
	public void testACL() {
		
		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// **mutual or external authentication only**
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB082, "87 00 20 FF");
		testPutKey(0x82, 0x6982);
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x82, 0x9000);
		deauthenticate();
		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// **pin authentication only**
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB083, "87 00 10 FF");
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x83, 0x6982);
		deauthenticate();
		authenticatePin();
		testPutKey(0x83, 0x9000);
		deauthenticate();
		
		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// pin authentication only or general authenticate
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB084, "87 00 30 FF");
		testPutKey(0x84, 0x9000);
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x84, 0x9000);
		deauthenticate();
		
		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// never
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB085, "87 00 FF FF");
		testPutKey(0x85, 0x6982);
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x85, 0x6982);
		deauthenticate();
		
		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// allowed
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB086, "87 00 00 FF");
		testPutKey(0x86, 0x9000);
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x86, 0x9000);
		deauthenticate();

		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// **pin authentication only**
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB087, "87 00 90 FF");
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x87, 0x6982);
		deauthenticate();
		authenticatePin();
		testPutKey(0x87, 0x9000);
		deauthenticate();
		
		//ACL: 10000111 
		// manage security environment
		// no restriction
		// put data
		// **mutual or external authentication only**
		// get data
		// never
		authenticatePin();
		createKeyFile(0xB088, "87 00 A0 FF");
		testPutKey(0x88, 0x6982);
		deauthenticate();
		authenticateGeneral();
		testPutKey(0x88, 0x9000);
		deauthenticate();
		
		// no ACL
		authenticatePin();
		execute("00E000001662148201188302B089A50BA4098001028301809501C0");
		execute("0044000000");
		testPutKey(0x89, 0x9000);
		deauthenticate();
		testPutKey(0x89, 0x9000);
		authenticateGeneral();
		testPutKey(0x89, 0x9000);
		deauthenticate();
		
		// media: contactonly operation
		authenticatePin();
		createKeyFile(0xB090, "87 00 91 FF");
		deauthenticate();
		testPutKey(0x90, 0x6982);
		simulator.changeProtocol("T=CL");
		testPutKey(0x90, 0x6982);
		authenticatePin();
		testPutKey(0x90, 0x6982);
		deauthenticate();
		simulator.changeProtocol("T=0");
		authenticatePin();
		testPutKey(0x90, 0x9000);
		deauthenticate();
		
		// media: contactless only operation
		authenticatePin();
		createKeyFile(0xB091, "87 00 92 FF");
		deauthenticate();
		testPutKey(0x91, 0x6982);
		authenticatePin();
		testPutKey(0x91, 0x6982);
		deauthenticate();
		simulator.changeProtocol("T=CL");
		testPutKey(0x91, 0x6982);
		authenticatePin();
		testPutKey(0x91, 0x9000);
		deauthenticate();
		simulator.changeProtocol("T=0");
	}
	
	@Test
	public void testPutGetData() {
		authenticatePin();
		// create an empty DO
		// check empty
		execute("00CBA010045C02DF2400", 0x6a88);
		// create
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", "DF24009000");
		// modify it
		execute("00DBA01005DF2402ABCD00");
		// check content
		execute("00CBA010045C02DF2400", "DF2402ABCD9000");
		// prune
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", "DF24009000");
		// delete
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", 0x6a88);
		// create
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", "DF24009000");
		// delete
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", 0x6a88);
		deauthenticate();
	}
	
	public void createKeyFile(int fileId, String acl) {
		byte[] bacl = DatatypeConverter.parseHexBinary(acl.replaceAll("\\s",""));
		
		execute("00 E0 00 00 " + String.format("%02X", bacl.length + 0x18) + " 62" + String.format("%02X", bacl.length + 0x16) + "82 01 18 83 02" + String.format("%04X", fileId) + "8C " + String.format("%02X", bacl.length) + DatatypeConverter.printHexBinary(bacl) + "A5 0B A4 09 80 01 02 83 01 80 95 01 C0");
		execute("0044000000");
	}
	
	@Test
	public void PutGetLargeData() {
		// save a something large like a certificate using chained apdu
		authenticatePin();
		execute("10 DB A0 10 F0 DF 24 82 02 9F 01 00 AA 02 78 DA 33 68 62 5A 66 D0 C4 D8 B7 80 99 89 91 89 49 C0 52 33 40 E6 B5 5B CE 0A A7 9E 87 FC DC C5 45 BD 06 BC 6C 9C 5A 6D 1E 6D DF 79 19 19 59 59 19 0C F8 0D 79 0D B8 D9 98 43 59 98 85 59 42 52 8B 4B 0C E4 C4 79 0D CD 0C 0C 0D 0D 80 A4 91 89 61 94 38 AF 11 32 17 53 43 13 A3 12 B2 A1 8C AC 0C CC 4D 8C FC 0C 40 71 2E A6 26 46 46 86 75 0B EB DE 18 D6 06 B7 F1 9D D5 FD 2E F5 20 29 FA 2C DB CF C5 8B 8C 3D 8A 0E 8B B3 7F 56 D3 FB 66 3C F1 A8 C4 84 37 7D 6B CB 73 8F 56 97 78 E7 C8 5F 73 3E E2 97 7A 55 52 7B 56 66 F2 AC FF 53 9F 33 5F 7B F1 A3 59 6E 41 F6 5E CD 42 86 15 FF 66 E8 F4 E6 DF 76 50 5F 75 38 EA EB 65 E1 35 5F 59 4A 27 F4 7D 8C 4F 59 17 FC C6 59 E8 4C 60 89 BD C3 97 CF DC F7 37 68 9C"); 
		execute("10 DB A0 10 F0 9A 2B 6B B2 65 21 CF BE 17 7B 75 94 1D 6C 26 54 2B 6E 8F BD 74 F7 83 56 B1 49 92 EE B9 3C 87 7F 96 86 67 2F DD 9E 7E 37 59 31 37 71 F7 AC 85 75 DF CF 4C E0 3B 71 F2 41 E5 F9 53 6E F2 E9 1E 1A 69 C5 0D 75 93 AA E7 D6 35 58 35 5C 13 ED AD 49 7A 9B 25 BD 67 BF F4 DD 8B 55 35 6A 91 BF 8F F5 DF E6 EF 0B 5B 92 1F 11 77 C3 ED 9B 7E D7 BF BD 66 06 EF 75 6E 36 9A AF E7 FD 72 EA 42 C9 8B D9 0F 6E 2E 70 B6 BC 5F 7D 9E 69 DF CD 49 5D 82 11 AB 8B 7F 2D 8E 64 62 66 64 60 44 0B 76 66 50 C0 4C 65 57 F8 1D 10 7E 38 FA 97 CF F2 E6 CA 29 46 BE AA 5E D9 4C 53 3C BC E7 48 D4 CD 0D 63 B0 FD CD F8 FA D7 F3 9E 7B BC 59 4F 9A D2 94 B7 7C 8F FE 54 91 11 38 F9 BB 77 C0 A2 1F FF F6 BC 58 91 F6 E1 93 CD D4 FF 01 B5 0F 36 7B 3E AB BF 55 74");
		execute("00 DB A0 10 C4 B7 72 AA A8 78 C9 7A 73 9B 1D 67 73 4D B7 B2 DE B6 0F 08 77 9E 70 7F E1 DE 95 1B BF 73 5D 68 E5 DD D1 5F C0 60 FA D9 FB DF 16 AE A7 E7 C2 F9 3A 5E ED 92 7F EE B4 F1 F4 9B 99 B2 13 CE 25 0A 4F 3D DD D9 9D DE 97 E3 DE 33 C1 E9 89 84 F8 8E 3F 06 E5 89 3C 93 1D CB 4F 74 A8 73 8A 31 04 AC EA B3 48 75 BD BA 60 E3 E3 05 2D FF 97 F7 FD 67 EB FC 5E BD 30 FC D0 65 83 A5 C2 0C 6E 6F FB 5F 3B DD 33 E0 F8 37 47 22 2C F9 D9 F2 57 7D B7 2C 56 C4 4D E8 7D FB 44 F4 97 3A 5B E3 EC F8 DF 2C 3F D7 F6 F1 BF E9 5E 75 50 E3 2A 9F 9D 4B C3 FE 6C 56 87 52 91 77 47 72 B9 96 DE FD EF BC 34 1C 00 4D 16 29 3D");
		deauthenticate();
		// read it and compare it
		execute("00 CB A0 10 04 5C 02 DF 24 00", 
				"DF 24 82 02 9F 01 00 AA 02 78 DA 33 68 62 5A 66 D0 C4 D8 B7 80 99 89 91 89 49 C0 52 33 40 E6 B5 5B CE 0A A7 9E 87 FC DC C5 45 BD 06 BC 6C 9C 5A 6D 1E 6D DF 79 19 19 59 59 19 0C F8 0D 79 0D B8 D9 98 43 59 98 85 59 42 52 8B 4B 0C E4 C4 79 0D CD 0C 0C 0D 0D 80 A4 91 89 61 94 38 AF 11 32 17 53 43 13 A3 12 B2 A1 8C AC 0C CC 4D 8C FC 0C 40 71 2E A6 26 46 46 86 75 0B EB DE 18 D6 06 B7 F1 9D D5 FD 2E F5 20 29 FA 2C DB CF C5 8B 8C 3D 8A 0E 8B B3 7F 56 D3 FB 66 3C F1 A8 C4 84 37 7D 6B CB 73 8F 56 97 78 E7 C8 5F 73 3E E2 97 7A 55 52 7B 56 66 F2 AC FF 53 9F 33 5F 7B F1 A3 59 6E 41 F6 5E CD 42 86 15 FF 66 E8 F4 E6 DF 76 50 5F 75 38 EA EB 65 E1 35 5F 59 4A 27 F4 7D 8C 4F 59 17 FC C6 59 E8 4C 60 89 BD C3 97 CF DC F7 37 68 9C 9A 2B 6B B2 65 21 CF BE 17 7B 75 94 1D 6C 26 54 61 00"); 
		execute("00 C0 00 00 00", 
				"2B 6E 8F BD 74 F7 83 56 B1 49 92 EE B9 3C 87 7F 96 86 67 2F DD 9E 7E 37 59 31 37 71 F7 AC 85 75 DF CF 4C E0 3B 71 F2 41 E5 F9 53 6E F2 E9 1E 1A 69 C5 0D 75 93 AA E7 D6 35 58 35 5C 13 ED AD 49 7A 9B 25 BD 67 BF F4 DD 8B 55 35 6A 91 BF 8F F5 DF E6 EF 0B 5B 92 1F 11 77 C3 ED 9B 7E D7 BF BD 66 06 EF 75 6E 36 9A AF E7 FD 72 EA 42 C9 8B D9 0F 6E 2E 70 B6 BC 5F 7D 9E 69 DF CD 49 5D 82 11 AB 8B 7F 2D 8E 64 62 66 64 60 44 0B 76 66 50 C0 4C 65 57 F8 1D 10 7E 38 FA 97 CF F2 E6 CA 29 46 BE AA 5E D9 4C 53 3C BC E7 48 D4 CD 0D 63 B0 FD CD F8 FA D7 F3 9E 7B BC 59 4F 9A D2 94 B7 7C 8F FE 54 91 11 38 F9 BB 77 C0 A2 1F FF F6 BC 58 91 F6 E1 93 CD D4 FF 01 B5 0F 36 7B 3E AB BF 55 74 B7 72 AA A8 78 C9 7A 73 9B 1D 67 73 4D B7 B2 DE B6 0F 08 77 9E 70 7F E1 DE 95 1B BF 73 5D 68 E5 61 A4"); 
		execute("00 C0 00 00 A4", 
				"DD D1 5F C0 60 FA D9 FB DF 16 AE A7 E7 C2 F9 3A 5E ED 92 7F EE B4 F1 F4 9B 99 B2 13 CE 25 0A 4F 3D DD D9 9D DE 97 E3 DE 33 C1 E9 89 84 F8 8E 3F 06 E5 89 3C 93 1D CB 4F 74 A8 73 8A 31 04 AC EA B3 48 75 BD BA 60 E3 E3 05 2D FF 97 F7 FD 67 EB FC 5E BD 30 FC D0 65 83 A5 C2 0C 6E 6F FB 5F 3B DD 33 E0 F8 37 47 22 2C F9 D9 F2 57 7D B7 2C 56 C4 4D E8 7D FB 44 F4 97 3A 5B E3 EC F8 DF 2C 3F D7 F6 F1 BF E9 5E 75 50 E3 2A 9F 9D 4B C3 FE 6C 56 87 52 91 77 47 72 B9 96 DE FD EF BC 34 1C 00 4D 16 29 3D 90 00");
		authenticatePin();
		// prune
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", "DF24009000");
		// delete
		execute("00DBA01003DF240000");
		// check content
		execute("00CBA010045C02DF2400", 0x6a88);
		deauthenticate();
	}
	
	private void testPutKey(int fileId, int expectedReturn) {
		execute("00DB3FFF2670248401" + String.format("%02X", fileId) + "A51F87180102030405060708010203040506070801020304050607088803B073DC", expectedReturn);
	}

}
