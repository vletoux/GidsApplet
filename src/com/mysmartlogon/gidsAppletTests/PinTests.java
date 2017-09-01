package com.mysmartlogon.gidsAppletTests;

import static org.junit.Assert.*;

import java.util.Arrays;

import javax.smartcardio.ResponseAPDU;
import javax.xml.bind.DatatypeConverter;

import org.junit.Before;
import org.junit.Test;

import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;


public class PinTests extends GidsBaseTestClass {

    @Before
    public void setUp() throws Exception {
        super.setUp();
        createcard();
    }

    @Test
    public void testVerifyPin() {
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        // pin status
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
    }

    @Test
    public void testTooLongPin() {
        execute("00 20 00 80 20 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31", 0x63C3);
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
        execute("00 20 00 80 20 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31", 0x63C3);
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
    }

    @Test
    public void testTooShortPin() {
        execute("00 20 00 80 01 30", 0x63C3);
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
        execute("00 20 00 80 01 30", 0x63C3);
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
    }

    @Test
    public void testNonExistingPin() {
        execute("00 20 00 79 08 31 32 33 34 35 36 37 38", 0x6a88);
        // pin status
        execute("00 CB 3F FF 04 5C 02 7F 69 00", 0x6984);
    }

    @Test
    public void testVerifyPuk() {
        // puk is disabled
        execute("00200081083132333435363738", 0x6a88);
        execute("00 CB 3F FF 04 5C 02 7F 73 00", 0x6a88);
    }

    @Test
    public void AuthenticateAdminGeneral() {
        authenticateGeneral();
    }

    @Test
    public void AuthenticateAdminMutual() {
        authenticateMutual();
    }

    @Test
    public void WrongAuthenticateAdminGeneral() {
        byte[] key = DatatypeConverter.parseHexBinary("000000000000000000000000000000000000000000000000");
        authenticateGeneral(key, false);
        key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
        authenticateGeneral(key, true);
    }

    @Test
    public void WrongAuthenticateAdminMutual() {
        byte[] key = DatatypeConverter.parseHexBinary("000000000000000000000000000000000000000000000000");
        authenticateMutual(key, false);
        key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
        authenticateMutual(key, true);
    }

    @Test
    public void testPinFailure() {
        // good PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x63C2);
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701029301039000");
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x63C1);
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701019301039000");
        // good PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        execute("00 CB 3F FF 04 5C 02 7F 71 00", "7F71069701039301039000");
    }

    @Test
    public void testChangePIN() {
        // good pin
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        // change pin
        execute("00 24 00 80 10 31 32 33 34 35 36 37 38 31 32 33 34 35 36 37 37");
        // try old one
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38", 0x63C2);
        // try new one
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37");
        // change pin again
        execute("00 24 00 80 10 31 32 33 34 35 36 37 37 31 32 33 34 35 36 37 38");
    }

    @Test
    public void testBlockPin() {
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x63C2);
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x63C1);
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x63C0);
        // blocked
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x6983);
        // bad PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 37", 0x6983);

        byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
        authenticateGeneral(key, true);

        // unblock PIN
        execute("00 2C 02 80 08 31 32 33 34 35 36 37 38");
        // test PIN
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
    }

    @Test
    public void authenticateMutualReplayAttack() {
        byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
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
        globalchallenge[(short)39] = (byte) 0x80;
        cipherDES.init(deskey, Cipher.MODE_ENCRYPT);
        cipherDES.doFinal(globalchallenge, (short) 0, (short)40, challengeresponse, (short) 0);
        // send the response
        execute("00 87 00 00 2C 7C 2A 82 28" + DatatypeConverter.printHexBinary(challengeresponse), 0x9000);
        execute("00 87 00 00 2C 7C 2A 82 28" + DatatypeConverter.printHexBinary(challengeresponse), 0x6985);
    }

    @Test
    public void authenticateGeneralReplayAttack() {
        byte[] challenge, challengeresponse = new byte[8];
        byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
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
        execute("00 87 00 00 0C 7C 0A 82 08" + DatatypeConverter.printHexBinary(challengeresponse), 0x9000);
        execute("00 87 00 00 0C 7C 0A 82 08" + DatatypeConverter.printHexBinary(challengeresponse), 0x6985);
    }

    @Test
    public void bogusChallenge() {
        execute("00 87 00 00 00", 0x6984);
        execute("00 87 00 00 01 7c", 0x6984);
        execute("00 87 00 00 02 7c 00", 0x6984);
        execute("00 87 00 00 02 7c 01 00", 0x6984);
        execute("00 87 00 00 04 7c 02 79 00", 0x6984);
        execute("00 87 00 00 04 7c 02 82 00", 0x6984);
    }

    @Test
    public void bogusVerifyPin() {
        execute("00 2C 00 81 01 31", 0x6a86);
    }

}
