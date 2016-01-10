package com.mysmartlogon.gidsApplet;

import javacard.framework.Util;

public class ApplicationFile extends DedicatedFile {

	
	byte[] fileControlInformation = null;
	byte[] fileManagementData  = null;
	public ApplicationFile(short fileID, byte[] fileControlParameter, byte[] fileControlInformation, byte[] fileManagementData) {
		super(fileID, fileControlParameter);
		this.fileControlInformation = fileControlInformation;
		this.fileManagementData = fileManagementData;
	}

	/**
     * \brief Check if this is the AID of the application
     *
     * \param name The array containing the name to compare with the file's name.
     *
     * \param offset The offset at where the name begins.
     *
     * \param length The length of the name.
     *
     * \return false if the DF has no name or the names do not match,
     *			true else.
     */
    public boolean isName(byte[] name, short offset, short length) {
        short namePos;
        short aidlen = 0;
        short i;
        // Find the position of the AID tag (4F) in the fci.
        try {
            namePos = UtilTLV.findTag(fileControlInformation, (short)2, fileControlInformation[(short)1], (byte) 0x4F);
        } catch (NotFoundException e) {
            // This DF has no name.
            return false;
        } catch (InvalidArgumentsException e) {
            return false;
        }
        // This ADF has a AID.
        try {
        	aidlen = UtilTLV.decodeLengthField(fileControlInformation, (short)(namePos+1));
        	if (aidlen < length) {
                // aid len to check is to big to match
                return false;
            }
        } catch (InvalidArgumentsException e) {
            return false;
        }
        // Advance namePos from "tag" to value.
        try {
            namePos += 1 + UtilTLV.getEncodingLengthFieldLength(length);
        } catch(InvalidArgumentsException e) {
            return false;
        }
        // check if the name can be a part of the AID
        for (i = 0; i < (short)(aidlen - length +1); i++) {
			if ((byte)0 == Util.arrayCompare(name, offset, fileControlInformation, (short)(namePos + i), length) ) {
				return true;
			}
        }
         return false;
    }

	public byte[] getFileManagementData() {
		return fileManagementData;
	}
	
	public byte[] getFileControlInformation() {
		return fileControlInformation;
	}
}
