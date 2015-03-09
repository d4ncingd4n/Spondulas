********************************************************************************
*                                                                              *
*	            Spondulas - A program for Hunting Evil                         *
*                                                                              *
********************************************************************************

Contents
-----------
0.0 Disclaimer
1.0 Background
2.0 Requirements
3.0 Usage
4.0 FAQ

0.0 Disclaimer
---------------
There are no guarantees for this program. Pursuing malware may lead to having your computer compromised. Using this program may cause the Polar ice caps to melt and may endanger baby seals. Reasonable precautions have been taken in the coding of this program but, please realize the current "best practices" can become woefully inadequate overnight. Use at your own risk! 


1.0 Background
---------------
I began development of this tool to assist with investigating spearphishing attacks and collecting malware. Why would you want to investigate spearphishing attacks and collect malware? If you receive a spearphishing attack on your organization, how can you be sure that none of your users fell victim to the attack and were infected? Does your antivirus detect the malware payloads delivered? What vulnerabilites are being attacked? If someone is infected, what are the indicators of compromise? Are compromised servers used in the attack? If so, shouldn't someone notify them of a problem? Could the attack be coming from a remote file inclusion affecting multiple sites?

There are several challenges when investigating spearphishing attacks. The first challenge is retrieving the webpage without compromising your own computer. One approach is to use your usual webbrowser within a virtual machine. The problem with this approach is the server may perform multiple redirections of the webbrowser hiding the chain of redirections and concealing compromised hosts used to serve the attacks. The attack may target a different operating system or web browser then the one you are using. The attacker may read their server logs to see who is visting their site or may block specific IP addresses. Finally, if the attacker is using an exploit for your webbrowser, it may crash your webbrowser before you can analyize the attack.

The goal of Spondulas is to help investigate suspicious web pages while reducing the risk of infection. Please keep in mind that it is not magic and reasonable precautions should be taken while investigating potentially hostile web pages.

2.0 Requirements
-----------------
Spondulas is distributed as either a Python3 script or a compiled executable. Portable Python (http://www.portablepython.com/) is a good solution if you have a Windows system and do not wish to install the application or if you have a competing Python 2.x version installed. The compiled version is available in a W32 and x86_64 versions. The compiled version was created using cx_freeze (http://cx-freeze.sourceforge.net/). 

3.0 Usage
-----------
In the simpliest case, you can call the program by itself:

	python spondulas.py

This depends on python being in your path and having the spondulas.py script in the current working directory. If you do not have the python interpreter in your path, it is recommended to create an environment variable that points to the python interpreter. Please consult your operating system documentation for help creating an environment variable.

If spondulas is invoked without commandline options, it will enter interactive mode. In this mode, it will prompt you for the necessary information to complete the request. Interactive mode is also useful when you need to tune the parameters for the request instead of accepting the defaults.

A list of commandline options can be obtained by starting the program with the -h option.

	python spondulas.py -h

Verbose help mode can be called with the -hh option:

	python spondulas.py -hh

If you would like to accept certain defaults, you can call Spondulas with a minimal set of commandline options:

	python spondulas.py -u "http://www.example.com/some/random/page.html" -o output.txt

This will open the website listed in the -u parameter. In theory you can enclose the URL in single quotes (') but, double quotes (") seem to work better. The -o option designates an output file. This will capture the server response. Calling Spondulas this will make select a couple of defaults. It will select the default User Agent string. The current default user agent string pretends to be Internet Explorer 6 on Windows XP. A link filename is generated based on the defined output filename.

Keeping track of the redirection chains can be confusing. This can be addressed using the autolog mode. (Example given using the compiled version syntax.)

   spondulas -a -ref 'http://www.example.com/one.html' -u 'http://www.example.com/two.html' 

This creates an investigation file in the current directory with the current date as a filename. The investigation file will record the URLs accessed in a parent-child relationship of Referrer->URL. On each line, the IP address is recorded along with any cookies discovered on the link.

If you would like to process HTML file sent via e-mail, you can use the input mode of Spondulas.

    python spondulas -i email.txt

If you would like to track changes to a URL over time, you can use monitor mode. Monitor mode will poll the URL at user defined intervals. The server response is recorded in a time stamped file in the current directory. After it sleeps for the designated interval, it will request the same URL. If the IP address or page content changes, the response is saved in a new file in the current directory. If there is no change, no file is saved to conserve disk space.

    python spondulas -m -ms 3600 -ref "http://www.example.com/1.html" -u "http://www.example.com/2.html"

This example will poll the URL http://www.example.com/2.html with a referrer of http://www.example.com/1.html at intervals of 3,600 seconds (1 hour). If you don't know the number of seconds in a specific interval, you can call Spondulas without the -ms flag. This will prompt you for the desired sleep interval and do the calculations for you.

4.0 FAQ
---------

4.1 Why is the program named Spondulas?

The program is named in honor of my Grandmother. As the result of a childhood accident, she was severely disabled. Since my Grandmother was unable to walk into the woods behind the house, she would scare the grandchildren with tales of the "Spondulas" to keep them from going into the woods. The Spondulas was an animial that "looks like a moose but, has a bucket of water on one antler and a bucket of blackberries on the other." Yes, I know that was strange but, it effectively scared the daylights out of the kids. 
