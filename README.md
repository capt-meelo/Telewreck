# Telewreck
[![Version](https://img.shields.io/badge/Version-v1.0-green.svg)]()
[![Language](https://img.shields.io/badge/Language-Jython-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-red.svg)](https://github.com/capt-meelo/Telewreck/blob/master/LICENSE)


A Burp extension to detect and exploit versions of Telerik Web UI vulnerable to [CVE-2017-9248](https://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness). This extension is based on the original exploit tool written by Paul Taylor ([@bao7uo](https://twitter.com/bao7uo)) which is available at [https://github.com/bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto). Credits and big thanks to him. 

A related blog post on how to exploit web applications via Telerik Web UI can also be found [here](https://capt-meelo.github.io/pentest/2018/08/03/pwning-with-telerik.html).

### Features
* Detect vulnerable versions of Telerik Web UI during passive scans.
* Bruteforce the key and discover the "Document Manager" link just like the original exploit tool.


### Screenshots
![Passive Scan](/images/01.png)

![Telewreck Tab](/images/02.png)


### Installation

1. Download [telewreck.py](https://raw.githubusercontent.com/capt-meelo/Telewreck/master/telewreck.py) to your machine.
2. Install Python's **requests** module using `sudo pip install requests`.
2. On your Burp, go to _**Extender > Options**_ tab. Then under the **Python Environment** section, locate your **jython-standalone-2.7.0.jar** file (1) and the directory where Python's requests module is located (2).
![Burp Tab](/images/03.png)
3. Go to _**Extender > Extensions**_ tab, then click on the _**Add**_ button. On the new window, browse the location of **telewreck.py** and click the _**Next**_ button.
![Load Telewreck](/images/04.png)
4. If there's any error, the **Telewreck** tab would appear in your Burp. 
![Load Success](/images/05.png)


### Notes
1. This extension requires Python's **requests** module. Just run `pip install requests` to install it.
2. The text area under Telewreck tab doesn't function as a console. So, `stoud` and `stderr` outputs cannot be seen there. However, you can view them under the **Output** and **Errors** sections of the **Extender** tab.
3. Before running another bruteforce, cancel the current process first by clicking the **Cancel** button.
4. If the key can't be bruteforced, then probably the key has been set up securely and/or the application is not using a default installation of Telerik.
5. If the key can't be bruteforced and/or there are some issues, it's recommended to fall back to the original exploit tool. 


### To Do
1. Locate Telerik.Web.UI.DialogHandler.aspx

<br>
<br>

_**PS:** This is my first time developing a tool so apologies for the poor coding style. Feel free to contribute and improve the development of this tool._

_**Disclaimer:** This tool is created for educational purposes only._
