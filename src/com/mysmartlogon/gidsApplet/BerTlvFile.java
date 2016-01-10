package com.mysmartlogon.gidsApplet;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class BerTlvFile extends ElementaryFile {

	private static final short ELEMENT_COUNT_START = 10;
    private static final short ELEMENT_COUNT_MAX = 30; // set to max. 16383
	
    private Record[] children;
    private byte currentNumChildren;
    
	 /**
     * \brief Instantiate a new BER-TLV EF. No data is being added at this point.
     *
     * \param fileControlInformation The array of bytes containing the valid (!) File Control Information.
     *				It must contain the File ID (Tag 83). No Copy is made.
     *
     * \param maxRecords The maximum amount of saved records.
     *
     * \attention No copy of the FCI is made. Do not pass any buffer that is altered
     *				later (e.g. the apdu buffer). Max length 257 bytes as the length
     *				of the FCI Tag (6F) must be a byte.
     *
     * \attention To be safe, use IsoFileSystem.getSafeFile() to instantiate files.
     *
     * \throw IllegalArgumentException If necessary tags in the FCI are missing.
     */
	public BerTlvFile(short fileID, byte[] fileControlInformation) {
		super(fileID, fileControlInformation);
		this.children = new Record[ELEMENT_COUNT_START];
		this.currentNumChildren = 0;
	}

	@Override
	void clearContents() {
		short i;

        for(i = 0; i < currentNumChildren; i++) {
        	children[i].clearContents();
            children[i] = null;
        }

	}
	
	/**
     * \brief Delete a DO
     *
     * This method requests garbage collection.
     *
     * \param childNum internal index
     */
    protected void deleteChildren(short childNum) {

        children[childNum] = null;
        currentNumChildren--; // We have one less children now.

        // Fill up empty field in children array.
        // The last children is one ahead, so it is at currentNumChildren.
        if(childNum < currentNumChildren) {
            children[childNum] = children[currentNumChildren];
        }

        // Clean up the old file object.
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }

    /**
     * \brief remove a DO
     *
     * \param children The children to add.
     *
     * \throw NotEnoughSpaceException If CHILDREN_COUNT_MAX is reached.
     * @param size 
     * @param offset_cdata 
     */
    public Record addChildren(byte[] buffer, short offset, short wholelength, short lengthavailable) throws NotEnoughSpaceException {
    	// try to find a previous TLV
    	short i;
    	short lengthToCopy = (lengthavailable > wholelength ? wholelength: lengthavailable);
    	for(i = 0; i < currentNumChildren; i++) {
        	byte[] value = children[i].GetData();
        	
            if (UtilTLV.IsBERTLVTagEqual(buffer, offset, (short) (offset + lengthavailable), value)) {
            	// found => replace or erase ?
            	
            	// erase if empty DO pushed and already empty DO stored
            	short oldlen = UtilTLV.GetBERTLVDataLen(value, (short) 0, (short) value.length);
            	short newlen = UtilTLV.GetBERTLVDataLen(buffer, offset, (short) (offset + lengthavailable));
            	if (oldlen == 0) {
            		if (newlen == 0) {
            			deleteChildren(i);
            			return null;
            		}
            	}
            	// replace
            	if (oldlen == newlen) {
            		// no need to add / remove data, just replace the buffer
            		Util.arrayCopyNonAtomic(buffer, offset, value, (short) 0, lengthToCopy);
            	} else {
            		// remove previous data, add new
	            	byte[] data = new byte[wholelength];
	                Util.arrayCopyNonAtomic(buffer, offset, data, (short) 0, lengthToCopy);
	            	children[i] = null;
	            	if(JCSystem.isObjectDeletionSupported()) {
	                    JCSystem.requestObjectDeletion();
	                }
	            	children[i] = new Record(data);
            	}
            	return children[i];
            }
            
        }
        
    	
        // First we have to check for enough space.
        if(currentNumChildren >= (short)children.length) {
        	Record[] newChildren = null;
            // The array is full - we try to increase the size.
            if((short)(children.length * 2) <= ELEMENT_COUNT_MAX) {
                // Doubling the size is possible.
                newChildren = new Record[(short)(children.length * 2)];
                copyFileArrayRefs(children, newChildren);
            } else {
                // Doubling not possible - try to at least increase to CHILDREN_COUNT_MAX.
                if(currentNumChildren < ELEMENT_COUNT_MAX) {
                    newChildren = new Record[ELEMENT_COUNT_MAX];
                    copyFileArrayRefs(children, newChildren);
                } else {
                    // CHILDREN_COUNT_MAX exceeded. No "space" left. Fail.
                    throw NotEnoughSpaceException.getInstance();
                }
            }
            children = newChildren; // Initial children array is now garbage.
            if(JCSystem.isObjectDeletionSupported()) {
                JCSystem.requestObjectDeletion();
            }
        } // We have enough space (now).
        byte[] data = new byte[wholelength];
        Util.arrayCopyNonAtomic(buffer, offset, data, (short) 0, lengthToCopy);
        children[currentNumChildren++] = new Record(data);
        return children[(short) (currentNumChildren-1)];
    }

    /**
     * \brief Copies the references from one File array to the other.
     *
     * \attention Although only references are copied, this is probably still quite expensive because
     * writing to the EEPROM is. Only use this for operations that are not called often (Creating and deleting files etc.).
     *
     * \param src The source File array to copy from.
     *
     * \param dest The destination File array to copy to. It MUST be at least of size of the src array.
     */
    private static void copyFileArrayRefs(Record[] src, Record[] dest) {
        short i = 0;
        short length = src.length > dest.length ? (short)dest.length : (short)src.length;

        for(i=0; i < length; i++) {
            dest[i] = src[i];
        }
        return;
    }

	public Record getData(byte[] tag, short offset, short len) throws NotFoundException {
		short i;

        for(i = 0; i < currentNumChildren; i++) {
        	byte[] value = children[i].GetData();
        	if(UtilTLV.IsBERTLVTagEqual(tag, offset, len, value)) {
                return children[i];
            }
        }

        throw NotFoundException.getInstance();
	}

	public Record[] getAllData() {
		return children;
	}

}
