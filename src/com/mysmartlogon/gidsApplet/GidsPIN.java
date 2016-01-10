package com.mysmartlogon.gidsApplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

/**
 * \brief The IsoPIN class.
 *
 * Allows the PIN to be deauthenticated
 */

public class GidsPIN extends OwnerPIN {

	
	private byte currentPINLen = 0;
	private byte minPINSize = 0;
	private byte maxPINSize = 0;
	private byte tryLimit = 0;
	
	public GidsPIN(byte tryLimit, byte maxPINSize, byte minPINSize) {
		super(tryLimit, maxPINSize);
		this.maxPINSize = maxPINSize;
		this.tryLimit = tryLimit;
		this.minPINSize = minPINSize;
	}
	
	public byte GetCurrentPINLen() {
		return currentPINLen;
	}
	
	public byte GetMinPINSize() {
		return minPINSize;
	}
	
	public byte GetMaxPINSize() {
		return maxPINSize;
	}
	
	public void CheckLength(byte len) {
		if (len < minPINSize || len > maxPINSize) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}
	
	public void setAsAuthenticated() {
		this.setValidatedFlag(true);
	}
	
	@Override
	public void update(byte[] pin,
            short offset,
            byte length) {
		super.update(pin, offset, length);
		currentPINLen = length;
	}

	public byte getTryLimit() {
		return tryLimit;
	}

}
