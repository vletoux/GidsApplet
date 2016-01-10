package com.mysmartlogon.gidsApplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;

public class CRTKeyFile extends ElementaryFile {

	private final short posCRT;
	private final short lenCRT;
	//private final byte keyId;
	
	private KeyPair keyPair = null;
	private byte[] symetricKey = null;
	
	public CRTKeyFile(short fileID, byte[] fileControlInformation, short pos, short len) {
		super(fileID, fileControlInformation);
		posCRT = pos;
		lenCRT = len;
		//keyId = (byte) (fileID & 0xFF);
	}

	public static void CheckCRT(byte[] fcp, short pos, short len) throws InvalidArgumentsException {
		if (len < 11 || len > 127) {
			throw InvalidArgumentsException.getInstance();
		}
		/*short innerOffset = (short) (pos + 2);
		short innerLength = (short) (len - 2);
		// Search the CRT tag (A5). If not found, then raise an error
        try {
            pos = UtilTLV.findTag(fcp, innerOffset, innerLength, (byte) 0xA4);
            len = UtilTLV.decodeLengthField(fcp, (short)(pos+1));
        } catch (NotFoundException e) {
        	throw InvalidArgumentsException.getInstance();
        }*/
	}
	
	@Override
	void clearContents() {
		if (keyPair != null) {
			keyPair.getPrivate().clearKey();
		}
	}

	private void ClearKeys() {
		if (symetricKey != null) {
			symetricKey = null;
		}
		if (keyPair != null) {
			keyPair.getPrivate().clearKey();
		}
		if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
	}
	
	public void SaveKey(KeyPair kp) {
		ClearKeys();
		keyPair = kp;
	}

	public KeyPair GetKey() {
		return keyPair;
	}

	public void CheckUsage(byte operation, byte algRef) throws NotFoundException {
		short innerPos = (short) (posCRT+2), pos = 0;
		short innerLen = 0, len = 0;
		boolean found = false;
		while( !found) {
		// Search the operation tag. If not found, then raise an error
	        try {
	        	innerPos = UtilTLV.findTag(fcp, innerPos, lenCRT, operation);
	        	innerLen = UtilTLV.decodeLengthField(fcp, (short)(innerPos+1));
	        } catch (NotFoundException e) {
	        	throw NotFoundException.getInstance();
	        } catch (InvalidArgumentsException e) {
	        	throw NotFoundException.getInstance();
			}
	        try {
		        pos = UtilTLV.findTag(fcp, (short) (innerPos+2), innerLen, (byte) 0x80);
	        	len = UtilTLV.decodeLengthField(fcp, (short)(pos+1));
	        	if (len != 1) {
	        		throw InvalidArgumentsException.getInstance();
	        	}
	        	byte ref = fcp[(short) (pos+2)];
	        	if (algRef == ref) {
	        		found = true;
	        		break;
	        	}
	        } catch (NotFoundException e) {
	        	// search next tag
	        	continue;
	        } catch (InvalidArgumentsException e) {
	        	throw NotFoundException.getInstance();
			}
	        innerPos += 2;
	        innerPos += innerLen;
		}
		if (!found) {
			throw NotFoundException.getInstance();
		}
	}

	public void importKey(byte[] buffer, short offset, short length) throws InvalidArgumentsException {
		// focused on A5 tag
		short innerPos = 0, innerLen = 0;
		short pos = 0, len = 0;
		// keytype is missing for symetric key
		byte keytype = 1;
		byte keyref = 0;
		if (buffer[offset] != (byte) 0xA5) {
			throw InvalidArgumentsException.getInstance();
		}
		
		innerPos = (short) (offset + 1 + UtilTLV.getLengthFieldLength(buffer, (short) (offset+1)));
		innerLen = UtilTLV.decodeLengthField(buffer, (short) (offset+1));
		
		try {
			pos = UtilTLV.findTag(buffer, innerPos, innerLen, (byte) 0x83);
        	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
        	if (len != 1) {
        		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        	}
        	keytype = buffer[(short) (pos+2)];
		} catch (NotFoundException e) {
        	// optional tag: default = symetric key
        } catch (InvalidArgumentsException e) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		try {
			pos = UtilTLV.findTag(buffer, innerPos, innerLen, (byte) 0x84);
        	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
        	if (len != 1) {
        		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        	}
        	// key ref used to encrypt the imported key
        	keyref = buffer[(short) (pos+2)];
        	if (keyref != 0) {
        		ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        	}
		} catch (NotFoundException e) {
        	// optional tag: default = none
        } catch (InvalidArgumentsException e) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		try {
			pos = UtilTLV.findTag(buffer, innerPos, innerLen, (byte) 0x87);
        	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
        	
        	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
        	if (keytype == 1) {
        		importSymetricKey(buffer, pos, len);
        	} else if (keytype == 2) {
        		importRsaKey(buffer, pos, len);
        	} else {
        		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        	}
        } catch (Exception e) {
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
	}

	private void importRsaKey(byte[] buffer, short offset, short length) throws InvalidArgumentsException {
		
		short pos = offset;
		short len = 0;
		RSAPrivateCrtKey rsaPrKey = null;
		RSAPublicKey rsaPuKey = null;
		if (buffer[pos] != 0x30) {
			throw InvalidArgumentsException.getInstance();
		}
		len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	if (len > (short) (length +2)) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	// version; len=1 ; value = 0
    	if (buffer[pos++] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	if (buffer[pos++] != 0x01) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	if (buffer[pos++] != 0x00) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	// modulus
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	if ((len & 0x0F) == (byte) 1 && buffer[pos] == 0) {
    		len -= 1;
    		pos++;
    	}
		short keysize = (short) (len * 8);
		try {
			rsaPrKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keysize, false);
			rsaPuKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keysize, false);
		} catch(CryptoException e) {
			if(e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			}
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		}
		rsaPuKey.setModulus(buffer, pos, len);
		pos += len;
		// public exponent
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	
    	rsaPuKey.setExponent(buffer, pos, len);
    	pos += len;
		// private exponent
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	pos += len;
    	// P
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	// the minidriver may prepend a 00 before (len = len+1) and the javacard don't like it => remove the 00
    	if ((len & 0x0F) == (byte) 1 && buffer[pos] == 0) {
    		len -= 1;
    		pos++;
    	}
    	try {
    		rsaPrKey.setP(buffer, pos, len);
    	} catch(CryptoException e) {
            if(e.getReason() == CryptoException.ILLEGAL_VALUE) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    	pos += len;
    	// Q
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	if ((len & 0x0F) == (byte) 1 && buffer[pos] == 0) {
    		len -= 1;
    		pos++;
    	}
    	rsaPrKey.setQ(buffer, pos, len);
    	pos += len;
    	// d mod p-1
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	if ((len & 0x0F) == (byte) 1 && buffer[pos] == 0) {
    		len -= 1;
    		pos++;
    	}
    	rsaPrKey.setDP1(buffer, pos, len);
    	pos += len;
    	// d mod q-1
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	if ((len & 0x0F) == (byte) 1 && buffer[pos] == 0) {
    		len -= 1;
    		pos++;
    	}
    	rsaPrKey.setDQ1(buffer, pos, len);
    	pos += len;
    	// q-1 mod p
    	if (buffer[pos] != 0x02) {
    		throw InvalidArgumentsException.getInstance();
    	}
    	len = UtilTLV.decodeLengthField(buffer, (short)(pos+1));
    	pos += 1 + UtilTLV.getLengthFieldLength(buffer, (short)(pos+1));
    	if ((len & 0x0F) == (byte) 1 && buffer[pos] == 0) {
    		len -= 1;
    		pos++;
    	}
    	rsaPrKey.setPQ(buffer, pos, len);
    	pos += len;
		
    	if(rsaPrKey.isInitialized()) {
    		// If the key is usable, it MUST NOT remain in buf.
    		Util.arrayFillNonAtomic(buffer, offset, length, (byte)0x00);
    		ClearKeys();
			this.keyPair = new KeyPair(rsaPuKey, rsaPrKey);
    		if(JCSystem.isObjectDeletionSupported()) {
			    JCSystem.requestObjectDeletion();
			}
			
	  } else {
	      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	  }
	}

	private void importSymetricKey(byte[] buffer, short offset, short length) {
		ClearKeys();
		byte[] key = new byte[length];
		Util.arrayCopyNonAtomic(buffer, offset, key, (short) 0, length);
		this.symetricKey = key;
	}

	public byte[] GetSymectricKey() {
		return symetricKey;
	}
}
