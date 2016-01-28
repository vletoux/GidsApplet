# GidsApplet
Generic Identity Device Specification (GIDS) smart card is the only PKI smart card whose driver is integrated on each Windows since Windows 7 SP1 and which can be used read and write. No Windows driver installation is required and this card can be used instantly.

[My Smart Logon] (https://www.mysmartlogon.com/generic-identity-device-specification-gids-smart-card/)  is providing free of charge a javacard applet to transform a java card into a GIDS smart card and its integration in OpenSC for other operating systems (Linux, MacOSX, …).
#General requirements

* Java Card version 2.2.1 or above (see the list of [tested cards](https://www.mysmartlogon.com/generic-identity-device-specification-gids-smart-card/tested-cards/))
* Implementation of the “requestObjectDeletion()”-mechanism of the Java Card API is recommended to be able to properly delete files.
* Windows 7 SP1 / 2008 R2 or later for the minidriver ; OpenSC for pkcs11

#Download

[Download GidsApplet.cap] (https://github.com/vletoux/GidsApplet/releases)

#Building

You can use the card SDK to build the applet or [ant-javacard](https://github.com/martinpaljak/ant-javacard).

The continuous integration platform script ([.travis.yml](.travis.yml)) can be executed to build the applet.

#Installation

Install the CAP-file (GidsApplet.cap) to your Java Card smartcard (e.g. with GlobalPlatformPro).
The release section includes compiled version of the applet.

#Reference
* [GIDS specification] (http://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx)
* [minidriver specification] (http://msdn.microsoft.com/en-us/library/windows/hardware/dn631754%28v=vs.85%29.aspx) (for card initialization)
