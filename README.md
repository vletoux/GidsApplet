# GidsApplet

<!--
GidsApplet: A Java Card implementation of the GIDS (Generic Identity
Device Specification) specification
https://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx
Copyright (C) 2016  Vincent Le Toux(vincent.letoux@mysmartlogon.com)

SPDX-License-Identifier: GPL-3.0-or-later
-->

Generic Identity Device Specification (GIDS) smart card is the only PKI smart card whose driver is integrated on each Windows since Windows 7 SP1 and which can be used read and write. No Windows driver installation is required and this card can be used instantly.

[My Smart Logon](https://www.mysmartlogon.com/generic-identity-device-specification-gids-smart-card/)  is providing free of charge a javacard applet to transform a java card into a GIDS smart card and its integration in OpenSC for other operating systems (Linux, MacOSX, …).

3 years of use without any bug reported!

## General requirements

* Card requirements
  * Java Card version 2.2.1 or above (see the list of [tested cards](https://www.mysmartlogon.com/generic-identity-device-specification-gids-smart-card/tested-cards/))
  * Implementation of the "requestObjectDeletion()"-mechanism of the Java Card API is recommended to be able to properly delete files.
* Requirements to use the card
  * Windows 7 SP1 / 2008 R2 or later for the "minidriver"
  * OpenSC (any platform) for pkcs11

## Download

Download [GidsApplet.cap](https://github.com/vletoux/GidsApplet/releases)

## Installation on the smart card

Install the CAP-file (GidsApplet.cap) to your Java Card smartcard (e.g. with [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)).
The release section includes compiled version of the applet.

Most of the time, the applet can be installed with the command:

```sh
gp --install GidsApplet.cap --default
```

Some cards require additional switch like for G&D `-emv` or Gemalto `-visa2 -key`. See this [page](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/TestedCards) for more details.
MANY UNSUCCESSFUL GP COMMANDS (approx 10) CAN BRICK YOUR CARD. Contact your manufacturer for more information.

## Building

### General instructions

You can use the card SDK to build the applet or [ant-javacard](https://github.com/martinpaljak/ant-javacard).

The continuous integration platform script ([.travis.yml](.travis.yml)) can be executed to build the applet.

You will need to use JDK 11 to build.

### Building using VSCode

Install VSCode

![292740193-882d2611-0ff9-458e-90f8-43c19379c592](https://github.com/vletoux/GidsApplet/assets/10632326/d5bbb372-d886-43a1-b2f4-676680ee3d76)

Copy the code to a directory. Make sure you are downloading the submodules inside the ext directory.
Aka run `git submodule update --init --recursive`. If you download the source code as a .zip directly, the submodules will not be downloaded.

go to (https://aka.ms/vscode-java-installer-win) and run the installer to add the Coding Pack for java

![292740378-4fceff39-8176-48fe-a11c-860a90079952](https://github.com/vletoux/GidsApplet/assets/10632326/7840b064-dd92-4e6f-b213-590041e69d1e)

Once VSCode reloaded, install a JDK

![292740449-c0182143-bf51-4ceb-bdbf-35b0e0122cab](https://github.com/vletoux/GidsApplet/assets/10632326/8bc386fd-3f1e-4128-8be7-d8629c9a1409)

Select 11 Lts

![292740469-1432d82a-b2e0-4e7e-94cc-4a6eb4561cd2](https://github.com/vletoux/GidsApplet/assets/10632326/ee0dc98d-9b32-4fb6-a2bb-1d5554cec6c6)

and install it. Make sure JAVA_HOME will be populated.

![292740483-23853cdb-b962-47f4-b7ba-59a99a5a20e0](https://github.com/vletoux/GidsApplet/assets/10632326/2315d868-a5a2-4bef-9520-861d2b39ab55)

Install the extension [Ant Target Runner](https://marketplace.visualstudio.com/items?itemName=nickheap.vscode-ant)

Right click on the dist target on the Ant Target Runner at the bottom left and build

![image](https://github.com/vletoux/GidsApplet/assets/10632326/37185e05-5900-4b00-8f28-85ba560a007a)

The applet will be built automatically

![293085824-2d9d8bd2-b43b-4eb5-b828-1c3dbaa5b567](https://github.com/vletoux/GidsApplet/assets/10632326/3b084f04-9d75-4c0a-97bc-e54e6316dcbf)

Note: the ant build script will automatically download the packages that are needed to build the code

### Running unit tests

Click on the "Lab" icon to display the unit test section of VSCode

![image](https://github.com/vletoux/GidsApplet/assets/10632326/7c2218f3-6a17-46e2-97d2-859092d48aa5)

Select JUnit as the unit test framework

![image](https://github.com/vletoux/GidsApplet/assets/10632326/62dbf866-3dc5-4ddb-b639-d15f07cea4ef)

The JUnit package will be automatically downloaded, and that will fixes the missing JUnit imports in the code.

![image](https://github.com/vletoux/GidsApplet/assets/10632326/d956ca0b-ca72-4ab8-9109-a27220f5a49f)

### Known problems when building using VSCode

#### Getting a SDK mismatch

The ant complains about another SDK being used

![image](https://github.com/vletoux/GidsApplet/assets/10632326/4f9e48cc-5fd1-424a-ae5d-a01dbe356e78)

Solution:

You can change the runtime version when compiling

![293044417-9af1a705-29d2-4fad-974f-e5a720faa289](https://github.com/vletoux/GidsApplet/assets/10632326/b180e4d4-1a2f-46f8-b09c-9b5bdc110384)

You can also make sure that the JAVA_HOME environment variable points to the JDK 11. Here is a way to be sure that the variable is correctly set (don't forget to reboot vscode after any change).

![293085729-3b899b7d-1160-441a-82d7-0613b10e04ad](https://github.com/vletoux/GidsApplet/assets/10632326/b7e74d84-dcfd-4bbf-9857-7d77a69571d2)

#### The import javax.smartcardio cannot be resolved

The module java.smartcardio and javax.xml may not be found.

![image](https://github.com/vletoux/GidsApplet/assets/10632326/e08fa3ab-216e-425b-a135-af7d370f2403)

TODO: provide a step by step solution

## Reference

* [GIDS specification](http://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx)
* [minidriver specification](http://msdn.microsoft.com/en-us/library/windows/hardware/dn631754%28v=vs.85%29.aspx) (for card initialization)
