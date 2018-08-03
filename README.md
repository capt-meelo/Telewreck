# Telewreck
A Burp extension to detect and exploit versions of Telerik Web UI vulnerable to [CVE-2017-9248](https://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness). This extension is based on the original exploit tool written by Paul Taylor ([@bao7uo](https://twitter.com/bao7uo)) which is available at [https://github.com/bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto).

### Features
1. Detect vulnerable versions of Telerik Web UI during passive scans.
2. Bruteforce the key and discover the "Document Manager" link just like the original exploit tool.

### Screenshots
![Passive Scan](/images/01.png)

![Telewreck Tab](/images/02.png)


### Notes
1. This extension requires Python's **requests** module. Just run `pip install requests` to install it.
2. The text area under Telewreck tab doesn't function as a console. So, `stoud` and `stderr` outputs cannot be seen there. However, you can view them under the **Output** and **Errors** sections of the **Extender** tab.

### To Do
1. Locate Telerik.Web.UI.DialogHandler.aspx

<br>
<br>
_**PS:** This is my first time developing a tool so apologies for the poor coding style. Feel free to contribute and improve the development of this tool._

_**Disclaimer:** This tool is created for educational purposes only._
