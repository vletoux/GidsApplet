package com.mysmartlogon.gidsApplet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class TransmitManager {
	
	// a ram buffer for public key export (no need to allocate flash !)
	private static final short RAM_BUF_SIZE = (short) 1220;
	private byte[] ram_buf = null;
	// internal variables to do chaining
    private short[] chaining_cache = null;
    // store special object to returns or if null, use the ram buffer
    private Object[] chaining_object = null;

    // number of variables for the cache
    private static final short CHAINING_CACHE_SIZE = (short) 6;
    // index of the object (when sending Record[])
    private static final short CHAINING_OBJECT_INDEX = (short) 0;
    // current offset
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_POS = (short) 1;
    // max size (if ram buffer)
    private static final short RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING = (short) 2;
    // previous APDU data to check consistancy between chain
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_INS = (short) 3;
    private static final short RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2 = (short) 4;
    private static final short RAM_CHAINING_CACHE_PUT_DATA_OFFSET = (short) 5;
    // index of the object array
    private static final short CHAINING_OBJECT = (short) 0;
    private static final short PUT_DATA_OBJECT = (short) 1;
    
    public TransmitManager() {
    	ram_buf = JCSystem.makeTransientByteArray(RAM_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
    	chaining_cache = JCSystem.makeTransientShortArray(CHAINING_CACHE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        chaining_object = JCSystem.makeTransientObjectArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

    }

	private void Clear(boolean buffer) {
		if (buffer) {
			Util.arrayFillNonAtomic(ram_buf, (short)0, RAM_BUF_SIZE, (byte)0x00);
		}
		chaining_cache[CHAINING_OBJECT_INDEX] = 0;
		chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
		chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = 0;
		chaining_cache[RAM_CHAINING_CACHE_PUT_DATA_OFFSET] = 0;
        chaining_object[CHAINING_OBJECT] = null;
        chaining_object[PUT_DATA_OBJECT] = null;
	}
	
	public byte[] GetRamBuffer() {
		return ram_buf;
	}
	
	public void ClearRamBuffer() {
		Clear(true);
	}

	/**
     * \brief Parse the apdu's CLA byte to determine if the apdu is the first or second-last part of a chain.
     *
     * The Java Card API version 2.2.2 has a similar method (APDU.isCommandChainingCLA()), but tests have shown
     * that some smartcard platform's implementations are wrong (not according to the JC API specification),
     * specifically, but not limited to, JCOP 2.4.1 R3.
     *
     * \param apdu The apdu.
     *
     * \return true If the apdu is the [1;last[ part of a command chain,
     *			false if there is no chain or the apdu is the last part of the chain.
     */
    static boolean isCommandChainingCLA(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        return ((byte)(buf[0] & (byte)0x10) == (byte)0x10);
    }
	
	public void processChainInitialization(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
		// Command chaining checks & initialization
        if(chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != 0 || isCommandChainingCLA(apdu)) {
            short p1p2 = Util.getShort(buffer, ISO7816.OFFSET_P1);
            /*
             * Command chaining only for:
             * 	- PERFORM SECURITY OPERATION
             * 	- GENERATE ASYMMETRIC KEYKAIR
             * 	- PUT DATA
             * when not using extended APDUs.
             */
            if( (ins != GidsApplet.INS_PERFORM_SECURITY_OPERATION
                     && ins != GidsApplet.INS_GENERATE_ASYMMETRIC_KEYPAIR
                     && ins != GidsApplet.INS_PUT_DATA)) {
                ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
            }

            if(chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] == 0
                    && chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] == 0) {
                /* A new chain is starting - set the current INS and P1P2. */
                if(ins == 0) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = ins;
                chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = p1p2;
            } else if(chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] != ins
                      || chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] != p1p2) {
                /* The current chain is not yet completed,
                 * but an apdu not part of the chain had been received. */
                ISOException.throwIt(ErrorCode.SW_COMMAND_NOT_ALLOWED_GENERAL);
            } else if(!isCommandChainingCLA(apdu)) {
                /* A chain is ending, set the current INS and P1P2 to zero to indicate that. */
            	chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_INS] = 0;
            	chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_P1P2] = 0;
            }
        }

        // If the card expects a GET RESPONSE, no other operation should be requested.
        if(chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] > 0 && ins != GidsApplet.INS_GET_RESPONSE) {
        	// clear the buffer
        	Clear(true);
        }
		if (ins != GidsApplet.INS_PUT_DATA) {
			clearCachedRecord();
		}
	}
	
	/**
     * \brief Receive the data sent by chaining or extended apdus and store it in ram_buf.
     *
     * This is a convienience method if large data has to be accumulated using command chaining
     * or extended apdus. The apdu must be in the INITIAL state, i.e. setIncomingAndReceive()
     * might not have been called already.
     *
     * \param apdu The apdu object in the initial state.
     *
     * \throw ISOException SW_WRONG_LENGTH
     */
    public short doChainingOrExtAPDU(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive();
        short offset_cdata = apdu.getOffsetCdata();

        // Receive data (short or extended).
        while (recvLen > 0) {
            if((short)(chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] + recvLen) > RAM_BUF_SIZE) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
            }
            Util.arrayCopyNonAtomic(buf, offset_cdata, ram_buf, chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS], recvLen);
            chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] += recvLen;
            recvLen = apdu.receiveBytes(offset_cdata);
        }

        if(isCommandChainingCLA(apdu)) {
            // We are still in the middle of a chain, otherwise there would not have been a chaining CLA.
            // Make sure the caller does not forget to return as the data should only be interpreted
            // when the chain is completed (when using this method).
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
            return (short)0;
        } else {
            // Chain has ended or no chaining.
            // We did receive the data, everything is fine.
            // Reset the current position in ram_buf.
            recvLen = (short) (recvLen + chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]);
            chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = 0;
            return recvLen;
        }
    }
    
    /**
     * \brief Process the GET RESPONSE APDU (INS=C0).
     *
     * If there is content available in ram_buf that could not be sent in the last operation,
     * the host should use this APDU to get the data. The data is cached in ram_buf.
     *
     * \param apdu The GET RESPONSE apdu.
     *
     * \throw ISOException SW_CONDITIONS_NOT_SATISFIED, SW_UNKNOWN, SW_CORRECT_LENGTH.
     */
    public void processGetResponse(APDU apdu) {
        sendData(apdu);
    }

    /**
     * \brief Send the data from ram_buf, using either extended APDUs or GET RESPONSE.
     *
     * \param apdu The APDU object, in STATE_OUTGOING state.
     *
     * \param pos The position in ram_buf at where the data begins
     *
     * \param len The length of the data to be sent. If zero, 9000 will be
     *            returned
     */
    private void sendData(APDU apdu) {
        short le;
    	short remaininglen = 0;
    	byte data[] = null;
    	short pos = chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS];
    	if (chaining_object[CHAINING_OBJECT] == null) {
    		data = ram_buf;
    		remaininglen = chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING];
    	} else if (chaining_object[CHAINING_OBJECT] instanceof Record) {
    		Record record = (Record) (chaining_object[CHAINING_OBJECT]);
    		data = record.GetData();
    		remaininglen = (short) (((short) data.length) - pos);
    	} /* else if (chaining_object[CHAINING_OBJECT] instanceof Record[]) {
    		short index = chaining_cache[CHAINING_OBJECT_INDEX];
    		Record[] records = (Record[]) (chaining_object[CHAINING_OBJECT]);
    		data = records[index].GetData();
    		remaininglen = (short) (((short) data.length) - pos);
    		//TODO adjust with next object
    	}*/
    	// no buffer requested ? end the transfert
    	
    	le = apdu.setOutgoing();
        if(le <= 0) {
        	Clear(true);
        	return;
        	//ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
        
        
        // We have 256 Bytes send-capacity per APDU.
    	short sendLen = remaininglen > le ? le : remaininglen;
        apdu.setOutgoingLength(sendLen);
        /*if (chaining_object[CHAINING_OBJECT] instanceof Record[]) {
        	apdu.sendBytesLong(data, pos, sendLen);
        } else {*/
        	apdu.sendBytesLong(data, pos, sendLen);
        //}
        	
        chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS]+= sendLen;
        
        if (chaining_object[CHAINING_OBJECT] == null) {
        	chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] -= sendLen;
        }
        remaininglen -= sendLen;
        if(remaininglen > 0) {
        	short nextRespLen = remaininglen > 256 ? 256 : remaininglen;
            ISOException.throwIt( (short)(ISO7816.SW_BYTES_REMAINING_00 | nextRespLen) );
        } else {
        	Clear(true);
            return; //ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }
    
	public void sendRecord(APDU apdu, Record data) {
		Clear(true);
		chaining_object[CHAINING_OBJECT] = data;
		sendData(apdu);
	}
	
	public void sendRecords(APDU apdu, Record[] data) {
		Clear(true);
		chaining_object[CHAINING_OBJECT] = data;
		sendData(apdu);
	}
    
	public void sendDataFromRamBuffer(APDU apdu, short offset, short length) {
		Clear(false);
		chaining_cache[RAM_CHAINING_CACHE_OFFSET_CURRENT_POS] = offset;
		chaining_cache[RAM_CHAINING_CACHE_OFFSET_BYTES_REMAINING] = length;
		sendData(apdu);
	}

	/* functions used to cache a Record object for chained PUT DATA.
	 * We cannot use the ram buffer because it is too small. */
	public Record returnCachedRecord() {
		Object object = chaining_object[PUT_DATA_OBJECT];
		if (object != null && object instanceof Record) {
			return (Record) object;
		}
		return null;
	}

	public void setCachedRecord(Record record) {
		chaining_object[PUT_DATA_OBJECT] = record;
	}
	
	public short returnCachedOffset() {
		return chaining_cache[RAM_CHAINING_CACHE_PUT_DATA_OFFSET];
	}

	public void setCachedOffset(short offset) {
		chaining_cache[RAM_CHAINING_CACHE_PUT_DATA_OFFSET] = offset;
	}

	public void clearCachedRecord() {
		chaining_object[PUT_DATA_OBJECT] = null;
		chaining_cache[RAM_CHAINING_CACHE_PUT_DATA_OFFSET] = 0;
	}
}
