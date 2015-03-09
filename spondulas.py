#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        Spondulas
# Purpose:      This tool is used to retrieve malicious web pages for analysis
#
# Author:      Bart Hopper
#
# Created:     03/02/2012
# Licence:     FreeBSD 
# Copyright (c) 2012, Bart Hopper
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies, 
# either expressed or implied, of the FreeBSD Project.
#-------------------------------------------------------------------------------

################################################################################
#   Todo/Possible features:
################################################################################
#       Add support for additional useragents
#       Allow random selection of user agents?
#       Allow an external file list of user agents?
#       Automated WHOIS lookup added to -links file
#       hash of payloads
#       PDF reports
#       Add shellcode detection
################################################################################

#####################
#       Imports     #
#####################

import argparse
import gzip
import hashlib
import os
import re
import socket
import ssl
import string
import sys
import threading
import time

#########################
#   Global Variables    #
#########################

decoded =           0   # Flag to indicate either a chunked or gzipped file
results =           ''  # Results of query or parse. May be repurposed
version_id =        '1.0.1'

#-------------------------------#
#   Output related variables    #
#-------------------------------#
address_links =     ''  # Stores the address links retrieved from the target web page
autolog =           0   # Automatically generates filenames and creates and investigation file
css_links =         ''  # Stores the Cascading Style Sheets discovered when parsing
forms =             ''  # Stores Form information discovered when parsing
image_links =       ''  # Stores image links discovered when parsing
inputfile =         ''  # A local file to parse for links
ip_address =        ''  # IP address resolved from query
linksfile =         ''  # A file to list all links found when parsing
outputfile =        ''  # The data retrieved from a remote host. This is repurposed for input_mode
nextfile =          ''  # Next filename for autolog
script_links =      ''  # Collection of all scripts found while parsing
was_redirected =    ''  # Flag to indicate if a redirection was detected

#-------------------------------#
#   Request related variables   #
#-------------------------------#
ajax =              []  # Array to store AJAX queries
cookies =           ''  # Stores the cookies discovered when parsing
cookie_array =      []  # Stores Cookies for investigation report
persistent =        0   # Boolean to keep the connection open for AJAX/websockets
port =              0
referrer =          ''
request =           ''
socksport =         0
SSL =               ''
target_url =        ''
timeout =           30
webrequest =        {};

#-------------------------------#
#   Timer related variables     #
#-------------------------------#
days =              0
hours =             0
minutes =           0
monitormode =       0
seconds =           0
time_calculated =   0
total_seconds =     0

#################################
#   Begin Function Definitions  #
#################################

def create_investigation_filename():
    '''Creates the investigation filename'''
    a = time.localtime()
    month = '{:02d}'.format(a.tm_mon)
    mday = '{:02d}'.format(a.tm_mday)
    filename = str(a.tm_year) + '-' + month + '-' + mday + '.txt'
    return filename

def create_report():
    '''Creates the report for the screen and links file.'''
    outfile = open(linksfile,'w')

    if(len(inputfile) > 0):
        print('\nFile Processed: '+inputfile +'\n\n')
    else:
        print('\nTarget URL: '+ webrequest['host'] + webrequest['resource'])
        outfile.write('\nTarget URL: '+ webrequest['host'] + webrequest['resource'] + '\n')
        print('IP address: '+ip_address)
        outfile.write('IP address: '+ip_address+'\n')
        if(len(was_redirected)):
            outfile.write('Redirected: '+was_redirected+'\n')
        print('Referrer: '+ webrequest['referrer'])
        outfile.write('Referrer: '+ webrequest['referrer'] + '\n')
    # Create a string with the current date
    a = time.localtime()
    a2 = str(a[0]) + '-' + str('%02d' % a[1]) + '-' + str('%02d' % a[2]) + ' '
    a2 += str(a[3]) + ':' + str('%02d' % a[4]) + ':' + str('%02d' % a[5])
    print('Date/Time: ' + a2)
    outfile.write('Date/Time: ' + a2 + '\n')
    print('Output File: ' + outputfile)
    outfile.write('Output File: ' + outputfile + '\n')
    print('Links File: ' + linksfile)
    outfile.write('Links File: ' + linksfile + '\n')
    print('\n')
    outfile.write('\n')
    if (len(address_links)):
        print('\nAddress Links')
        outfile.write('\nAddress Links\n')
        print('-'*20)
        outfile.write('-'*20 + '\n')
        print(address_links)
        outfile.write(address_links + '\n')
    if (len(cookies)):
        print('\nCookies')
        outfile.write('\nCookies\n')
        print('-'*20)
        outfile.write('-'*20 + '\n')
        print(cookies)
        outfile.write(cookies + '\n')
    if (len(css_links)):
        print('\nCascading Style Sheets')
        outfile.write('\nCascading Style Sheets\n')
        print('-'*20)
        outfile.write('-'*20 + '\n')
        print(css_links)
        outfile.write(css_links + '\n')
    if (len(forms)):
        print('\nForms')
        outfile.write('\nForms\n')
        print('-'*20)
        outfile.write('-'*20 + '\n')
        print(forms)
        outfile.write(forms + '\n')
    if (len(image_links)):
        print('\nImage Links')
        outfile.write('\nImage Links\n')
        print('-'*20)
        outfile.write('-'*20 + '\n')
        print(image_links)
        outfile.write(image_links + '\n')
    if (len(script_links)):
        print('\nScript Links')
        outfile.write('\nScript Links\n')
        print('-'*20)
        outfile.write('-'*20 + '\n')
        print(script_links)
        outfile.write(script_links + '\n')
    sys.stdout.flush()
    outfile.flush()
    outfile.close()
    sys.exit()

def create_request():
    '''Creates the http request to send to the target machine'''
    request =[]
    request.append(webrequest['request_type']+
            ' '+ webrequest['resource']+ ' HTTP/1.1')
    request.append('Host: '+webrequest['host'])
    request.append('User-Agent: '+webrequest['user_agent'])
    request.append('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
    request.append('Accept-Language: en-us,en;q=0.5')
    request.append('Accept-Encoding: gzip, deflate')
    request.append('Connection: keep-alive')
    if(webrequest['referrer']):
        request.append('Referer: '+webrequest['referrer'])
    if(webrequest['cookies']):
        request.append(webrequest['cookies'])
    if(webrequest.get('content_length')):
        request.append('Content-Length: '+str(webrequest['content_length']))
    # Add more stuff here
    if(webrequest.get('postvars')):
        request.append('\n'+webrequest['postvars'])
    print('\n')
    r = ''
    for i in request:
        r += (i + '\r\n')
    r += '\r\n'
    return r

def dechunk(a):
    '''This function removes the segment lengths and fixes "Chunked" files'''
    global decoded
    dechunked = ''
    chunked = a.find(bytes('Transfer-Encoding: chunked','latin'))
    if(chunked > 0):
        decoded = 1
        first = a.find(bytes('\x0D\x0A\x0D\x0A','latin'))
        first += 4
        dechunked += a[:first].decode()
        dechunked = dechunked.encode()
        end = a.find(bytes('\x0D\x0A','latin'),first)
        chunklength = a[first:end]
        end += 2
        chunklength = int(chunklength,16)
        while chunklength:
            dechunked += a[end:end+chunklength]
            first = end+chunklength+2
            end = a.find(bytes('\x0D\x0A','latin'),first)
            chunklength = a[first:end]
            end += 2
            chunklength = int(chunklength,16)
    else:
        dechunked = a

    return dechunked

def demangle(response):
    '''Fix the escaping present in a bytes object'''
    if(response[0:2] == "b'"):

        response = response[2:]
        response = response[:-1]

        endline = bytes('\x5C\x72\x5C\x6E','latin')
        newline = bytes('\x0D\x0A','latin')
        response = response.replace(endline,newline)

        oldtab = bytes('\x5C\x74','latin')
        newtab = bytes('\x09','latin')
        response = response.replace(oldtab,newtab)

        oldapos = bytes('\x5C\x27','latin')
        newapos = bytes('\x27','latin')
        response = response.replace(oldapos,newapos)

        oldcr = bytes('\x5C\x0A','latin')
        newcr = bytes('\x0A','latin')
        response = response.replace(oldcr,newcr)

    return response

def generate_firefox_ua_string():
    '''Creates a Firefox Useragent string based on OS and Firefox version.'''
    print('\nLet\'s generate an Firefox user agent string....\n')
    ua_components = ['Mozilla/5.0 (',
                        ['Windows NT 5.1;',
                         'Windows NT 5.2;',
                         'Windows NT 6.0;',
                         'Windows NT 6.1;',
                         'Macintosh; Intel Mac OS X 10.6;',
                         'X11; Linux i686;',
                         'X11; Linux x86_64;',
                         'X11; Linux i686 on x86_64;',
                         'Android; Mobile;',
                         'Android; Tablet;'
                         ],
                         [') Gecko/20100101 Firefox/5.0',
                          ') Gecko/20110524 Firefox/5.0a2',
                          ') Gecko/20100101 Firefox/6.0',
                          ') Gecko/20110612 Firefox/6.0a2',
                          ') Gecko/20100101 Firefox/9.0',
                          ') Gecko/20100101 Firefox/9.0.1',
                          ') Gecko/2012010317 Firefox/10.0a4'
                          ') Gecko/20120421 Firefox/11.0'
                          ') Gecko/20120403211507 Firefox/12.0'
                          ') Gecko/20120405 Firefox/14.0a1'
                          ') Gecko/20120427 Firefox/15.0a1'
                         ]
                    ]
    print('\nSelect OS version:')
    print('------------------')
    os_version = -1
    while((int(os_version) < 0) or (int(os_version) > len(ua_components[1])-1)):
        for i in range(0,len(ua_components[1])):
            print(str(i)+': '+ua_components[1][i])
        os_version = input('\nPlease select: ')
        if(os_version == ''):
            os_version = -1

    print('Select Firefox version:')
    print('------------------')

    firefox_version = -1
    while((int(firefox_version) < 0) or(int(firefox_version) > len(ua_components[2])-1)):
        for i in range(0,len(ua_components[2])):
            print(str(i)+': '+ua_components[2][i])
        firefox_version = input('\nPlease select: ')
        if(firefox_version == ''):
            firefox_version = -1

    ua = ua_components[0] + \
         ua_components[1][int(os_version)] + \
         ua_components[2][int(firefox_version)]
    return(ua)

def generate_ie_ua_string():
    '''Creates an Internet Explorer Useragent string based on OS and IE version.'''
    print('\nLet\'s generate an Internet Explorer user agent string....\n')
    ua_components = ['Mozilla/',
                        ['4.0 (compatible; MSIE 6.0;',
                         '4.0 (compatible; MSIE 7.0;',
                         '5.0 (compatible; MSIE 8.0;',
                         '5.0 (compatible; MSIE 9.0;',
                         '5.0 (compatible; MSIE 10.0;',
                         '5.0 (compatible; MSIE 10.6;'],
                        [['Windows XP','Windows NT 5.1)'],
                         ['Windows Server 2003/XP 64-bit','Windows NT 5.2)'],
                         ['Windows Vista','Windows NT 6.0)'],
                         ['Windows 7','Windows NT 6.1)']
                        ]
                    ]
    print('Select IE version:')
    print('------------------')

    ie_version = -1
    while((int(ie_version) < 0) or(int(ie_version) > len(ua_components[1])-1)):
        for i in range(0,len(ua_components[1])):
            print(str(i)+': '+ua_components[1][i])
        ie_version = input('\nPlease select: ')
        if(ie_version == ''):
            ie_version = -1

    print('\nSelect OS version:')
    print('------------------')
    os_version = -1
    while((int(os_version) < 0) or (int(os_version) > len(ua_components[2])-1)):
        for i in range(0,len(ua_components[2])):
            print(str(i)+': '+ua_components[2][i][0])
        os_version = input('\nPlease select: ')
        if(os_version == ''):
            os_version = -1

    ua = ua_components[0] + \
         ua_components[1][int(ie_version)] + \
         ua_components[2][int(os_version)][1]
    return(ua)

def get_choices(choices,label):
    '''Creates menus for the program'''
    print('\n'+label)
    print('-'*len(label))
    for i in range(0,len(choices)):
        print(str(i) + '. ' + choices[i][0])

    choice = -1
    while((choice < 0) or (choice > (len(choices)-1))):
    	temp = input('\nSelect: ')
    	if(temp == ''):
    		choice = -1
    		continue
    	if(temp.isnumeric()):
    		choice = int(temp)
    	else:
    		choice = -1
    choices[int(choice)][1]()

def get_cookies():
    '''Allows input of cookies to submit to the target web site.'''
    print('\nCookies are used to track state on the same web site.')
    print('Enter any cookies that were set for this web site...\n')
    print('Cookies should be in the format: cookie1=value1; cookie2=value2\n')
    print('Enter each line separately. Press enter on a blank line to finish entering\n')
    answer = ''
    response = ''
    while(len(answer) == 0):
        answer = input('Cookies: ')
        if(len(answer)==0): break
        response += "Cookie: " + answer +'\n'
        answer = ''
    webrequest['cookies'] = response[:-1]

def get_default_user_agent():
    '''Selects the default browser Useragent string.'''
    # Todo: retrieve default user agent from a configuration file
    return 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)'

def get_input_user_agent():
    '''Allow the user to input a User agent'''
    a = input('User Agent: ')
    return a

def get_link_file(outfile):
    '''Creates a filename for links file based on the outputfile filename'''
    global linksfile
    if(len(linksfile)>0):
        return
    else:
        a = ''
        fileparts = outfile.rsplit('.',2)
        fileparts.insert(1,'.')
        fileparts[0] = fileparts[0] + '-links'
        a = a.join(fileparts)
        linksfile = a

def get_next_file():
    '''Looks in the current directory for the ceiling filename'''
    a = os.listdir()
    b = []
    for i in a:
        if re.findall('^\d\d\d\.txt',i):
            b.append(i)
    if(len(b)==0):
        return '{:03d}'.format(1)+'.txt'

    b.sort(reverse=1)
    nextfile = b[0]
    nextfile = nextfile.replace('.txt','')
    nextfile = int(nextfile)
    nextfile += 1
    return '{:03d}'.format(nextfile)+'.txt'

def get_options():
    '''Processes the commandline options'''
    global autolog
    global inputfile
    global linksfile
    global monitormode
    global outputfile
    global persistent
    global referrer
    global request
    global socksport
    global target_url
    global timeout
    global total_seconds

    parser = argparse.ArgumentParser(prog='spondulas',prefix_chars='-/',description='A program to retrieve web pages and parse the links',version='Beta '+version_id)
    parser.add_argument('-hh', help='Verbose Help',dest='verbosehelp',action='store_true',default='false')
    parser.add_argument('-a', '--autolog', help='Enable autogeneration of outputfiles and create an investigation file',dest='autolog',action='store_const',const=1)
    parser.add_argument('-i', '--input', help='The source file',dest='infile',metavar='InputFile',default='')
    parser.add_argument('-l', '--link', help='The file used to store the links retrieved',dest='linksfile',metavar='LinkFile',default='')
    parser.add_argument('-m', '--monitor', help='Enables site monitor mode. This polls a site for changes. Use cautiously!',dest='monitormode',action='store_const',const=1)
    parser.add_argument('-ms', '--monitor-seconds', help='Sleep seconds for monitor mode',dest='total_seconds',metavar='seconds',type=int,default='0')
    parser.add_argument('-o', '--output', help='The file used to store the page retrieved',dest='outputfile',metavar='OutputFile',default='')
    parser.add_argument('-p', '--persistent', help='Hold a persistent connection for websockets/AJAX',dest='persistent',action='store_const',const=1)
    parser.add_argument('-r', '--request', help='The request type either GET or POST',choices=('GET','POST'), dest='request',metavar='request',default='GET')
    parser.add_argument('-ref', '--referrer', help='The URL referring you to the new URL',dest='referrer',metavar='URL',default='')
    parser.add_argument('-s', '--socksport', help='The port number for a SOCKS5 proxy',dest='socksport',metavar='Port#',default='')
    parser.add_argument('-t', '--timeout', help='The Number of seconds to hold a keep-alive session open',dest='timeout',metavar='Seconds',default='30')
    parser.add_argument('-u', '--url', help='The URL to retrieve',dest='target_url',metavar='URL',default='')
#	parser.print_help()
    args =          parser.parse_args()
    autolog =       args.autolog
    verbosehelp =   args.verbosehelp
    inputfile =     args.infile
    linksfile =     args.linksfile
    outputfile =    args.outputfile
    monitormode =  args.monitormode
    persistent =    args.persistent
    referrer =      args.referrer
    request =       args.request
    timeout =       int(args.timeout)
    if(len(args.socksport)>0):
        socksport = int(args.socksport)
    target_url =    args.target_url
    total_seconds = args.total_seconds
    if(verbosehelp == True):
        help()

def get_output_file():
    '''Allows input of a filename to store web request results.'''
    global autolog
    global outputfile
    if(len(outputfile) > 0):
        return
    elif autolog == 1:
        outputfile = get_next_file()
        return
    else:
        print('\nPlease enter the output filename....')
        response = ''
        while(response == ''):
            response = input('Output File: ')
            if(os.path.exists(response)):
                print('\nFile already exists...')
                response = ''
        outputfile = response

def get_post_vars():
    '''Allows the input of the variables for a POST request.'''
    print('POST requests must have variables.')
    print('Please enter POST variables......\n')
    print('Format: parameter1=value&parameter2=value&parameter3=value....\n')
    response = ''
    while(response == ''):
        response = input('Post vars: ')
    webrequest['postvars'] = response
    webrequest['content_length'] = len(webrequest['postvars'])

def get_referrer():
    '''Allows entry of a referrer web page.'''
    global referrer
    if(len(referrer)>0):
        if(referrer[0]=="'") or (referrer[0]=='"'):
            referrer = referrer[1:]
        if(referrer[-1]=="'") or (referrer[-1]=='"'):
            referrer = referrer[:-1]
        webrequest['referrer'] = referrer
    else:
        print('\nEnter a referrer if you were redirected from another site.')
        print('If there is no referrer, you can leave this blank.\n')
        print('Referrer should be in the format: http://www.example.com/somepath/file.html\n')
        referrer = input("Referrer: ")
        webrequest['referrer'] = referrer

def get_request_type():
    '''Allows selection of GET or POST request type.'''
    if(len(request)>0):
        webrequest['request_type'] = request
        if(request == 'GET'):
            response = 0
        else:
            response = 1
    else:
        request_type = ['GET','POST']
        response = -1
        while ((int(response) < 0) or (int(response) > (len(request_type)-1))):
            print("\nRequest Type")
            print("--------------")
            for i in range(0,len(request_type)):
                print(str(i)+". "+request_type[i])

            response = input('\nSelect: ')
            if(response==''):
                response = -1
        if(int(response)!= 0):
            webrequest['content_length'] = 0
        print('\n')
        webrequest['request_type'] = request_type[int(response)]

    return int(response)

def get_response_address(response):
    '''Parses the web server response for any address links.'''
    global address_links
    temp = set ()
    addresses = re.findall(bytes('<a .*?href=[\'|\"](.*?)[\"|\']',encoding='latin1'),response,re.IGNORECASE)
    if(len(addresses)):
        for i in addresses:
            temp.add(str(i.decode()))
        addresses = ''
        for i in sorted(temp):
            address_links += i + '\n'

def get_response_cookies(response):
    '''Parses the retrieved web page for cookies.'''
    global cookies
    global cookie_array

    endline = bytes('\x5C\x72\x5C\x6E','latin')
    newline = bytes('\x0D\x0A','latin')
    response = response.replace(endline,newline)
    
    setcookie = re.findall(bytes('Set-Cookie: (.*)\n',encoding='latin1'),response,re.IGNORECASE)
    if(len(setcookie)):
        for i in setcookie:
            cookies += i.decode() +'\n'
            cookie_array.append(i.decode())
        setcookie = ''

def get_response_forms(response):
    '''Parses the retrieved web page for HTML forms.'''
    global forms
    form = re.findall(bytes('<form(.*?)</form>',encoding='latin1'),response,re.IGNORECASE)
    if(len(form)):
        for i in form:
            actionfield = re.search(bytes('action=[\'\"](.*?)[\'\"]',encoding='latin1'),i,re.IGNORECASE)
            methodfield = re.search(bytes('method=[\'\"](.*?)[\'\"]',encoding='latin1'),i,re.IGNORECASE)
            forms += actionfield.group(0).decode()
            forms += methodfield.group(0).decode() + '\n'
            actionfield = ''
            inputfields = re.findall(bytes('<input(.*?)/>',encoding='latin1'),i,re.IGNORECASE)
            for field in inputfields:
                typename = re.search(bytes('type=[\'|\"](.*?)[\'|\"]',encoding='latin1'),field,re.IGNORECASE)
                fieldname = re.search(bytes('name=[\'|\"](.*?)[\'|\"]',encoding='latin1'),field,re.IGNORECASE)
                fieldvalue = re.search(bytes('value=[\'|\"](.*?)[\'|\"]',encoding='latin1'),field,re.IGNORECASE)
                if (fieldname is not None):
                    forms += '\t'+typename.group(0).decode() + ' '+ fieldname.group(0).decode() +' '
                    if (fieldvalue is not None):
                        forms += "'"+fieldvalue.group(0).decode()+"'"+'\n'
                    else:
                        forms += "''" +'\n'
            inputfields = ''

            ##forms += i.decode() +'\n'

    form = ''

def get_response_images(response):
    '''Parses the web server response for a listing of image links.'''
    global image_links
    addresses = re.findall(bytes('<img .*?src=[\'|\"](.*?)[\"|\']',encoding='latin1'),response,re.IGNORECASE)
    if(len(addresses)):
        for i in addresses:
            image_links += str(i.decode()) + '\n'
        addresses = ''

def get_response_redirects(response):
    '''Searches responses for HTTP 3xx responses that indicate a redirection'''
    global was_redirected
    redirected = re.match(bytes('HTTP/1.1 3\d\d',encoding='latin1'),response,re.IGNORECASE)
    if(redirected):
        was_redirected = 'Yes'
    if(was_redirected):
        gohere = re.findall(bytes('[Ll]ocation: (.*)',encoding='latin1'),response,re.IGNORECASE)
        if(gohere):
            for i in gohere:
                print('\n\n[*] Redirect: '+ i.decode())
                was_redirected = i.decode()
    b = re.search(bytes('window.location *= *[\'|\"](.*?)[\'|\"]',encoding='latin1'),response,re.IGNORECASE)
    if(b):
        redirect_message = '[*] Redirect: '+str(b.group().decode())+'  *'
        print('\n\n\n')
        print('*'*(len(redirect_message)))
        print(redirect_message)
        print('*'*(len(redirect_message)))
        was_redirected = b.group().decode()

def get_response_external_scripts(response):
    '''Parses the web server response for a listing of image links.'''
    global script_links
    addresses = re.findall(bytes('<script .*?src=[\'|\"](.*?)[\"|\'].*?<\/script>',encoding='latin1'),response,re.IGNORECASE)
    temp = set ()
    if(len(addresses)):
        for i in addresses:
            temp.add(str(i.decode()))
        addresses = ''
        for i in sorted(temp):
            script_links += i + '\n'

def get_response_stylesheets(response):
    '''Parse the web server response for a listing of style sheets'''
    global css_links
    addresses = re.findall(bytes('<link .*?href=[\'|\"](.*?)[\"|\']',encoding='latin1'),response,re.IGNORECASE)
    if(len(addresses)):
        for i in addresses:
            css_links += str(i.decode()) + '\n'
        addresses = ''

def get_target_url():
    '''Get the target URL to retrieve.'''
    global port
    global SSL
    global target_url
    if(len(target_url)>0):
        if(target_url[-1] == "'"):
            target_url = target_url[1:-1]
        webrequest['URL'] = target_url
        print(webrequest['URL'])
    else:
        webrequest['URL'] = input('\nTarget URL: ')

    if(webrequest['URL'][0:5] == 'https'):
        port = 443
        SSL = True
        webrequest['protocol'] = 'https'
        host = re.sub('^https://','',webrequest['URL'],re.IGNORECASE)
    else:
        port = 80
        SSL = False
        webrequest['protocol'] = 'http'
        host = re.sub('^http://','',webrequest['URL'],re.IGNORECASE)
    host = re.sub('/.*','',host)
    colon = host.find(':')
    if(colon>0):
        port = int(host[int(colon)+1:])
        host = host[:colon]
    webrequest['host'] = host
    resource = webrequest['URL']
    resource = re.sub('(https*://)*'+host,'',resource)
    if(resource==""):
        resource = "/"
    if(resource[0]==':'):
        resource = re.sub(':\d{1,5}','',resource)
    webrequest['resource'] = resource

def get_user_agent():
    '''Allows selection of the browser Useragent string.'''
    if(len(sys.argv)>1):
        webrequest['user_agent'] = get_default_user_agent()
    else:
        dispatch = [['Use default user agent',get_default_user_agent],
                    ['Generate Internet Explorer user agent',generate_ie_ua_string],
                    ['Generate Firefox user agent',generate_firefox_ua_string],
                    ['Input Custom User Agent',get_input_user_agent]
                   ]
        print('\nSelect useragent')
        print('----------------\n')
        selection = -1
        while((int(selection) < 0) or(int(selection) > len(dispatch)-1)):
            for i in range(0,len(dispatch)):
                print(str(i)+': '+dispatch[i][0])
            selection = input('\nPlease select: ')
            if(selection == ''):
                selection = -1
        #webrequest['user_agent'] = 'Mozilla/4.0(compatible; MSIE 7.0b; Windows NT 6.0)'
        ua_function = dispatch[int(selection)][1]
        webrequest['user_agent'] = ua_function()

def help():
    '''Main Help Function'''
    a = '''

                            Spondulas Help


        '''
    print(a)
    while 1:
        dispatch = [['About',help_about],
                    ['Features',help_features],
                    ['File Transfers',help_file_transfers],
                    ['Processing HTML files',help_inputfiles],
                    ['Using TOR',help_tor],
                    ['Monitor Mode',help_monitor_mode],
                    ['Exit',sys.exit]
                    ]
        get_choices(dispatch,'Select: ')

def help_about():
    '''Main help screen'''
    a = '''
    Title:      Spondulas
    Purpose:    A program to retrieve and parse web pages
    Author:     Bart Hopper (@d4ncingd4n)
    '''
    print(a)

def help_features():
    '''Help Screen that lists significant features'''
    a = '''
    Features
    -----------
    * Support for GET and POST methods
    * Support for HTTP and HTTPS methods
    * Support for the submission of cookies
    * Support for SOCKS5 proxy using TOR
    * Support for pipelining (AJAX)
    * Monitor mode to poll a website looking for changes in DNS or body content
    * Input mode to parse local HTML files, e.g., e-mailed forms
    * Automatic conversion of GZIP and Chunked encoding
    * Automatic IP address Lookup
    * Selection or generation of User Agent Strings
    '''
    print(a)

def help_file_transfers():
    '''Help screen that explains http chunked encoding'''
    a = '''
    Spondulas automatically decodes gzip and chunked files in a
    "-decoded" file. The original file is also preserved.

    Binary files are often transfered as a 'chunked' encoding. When
    looking at the response from the server, you can identify a
    chunked file transfer by the 'Transfer-Encoding' header in the
    server response. Here is an example:

    HTTP/1.1 200 OK
    Date: Sat, 18 Feb 2012 05:37:47 GMT
    Server: Apache
    X-Powered-By: PHP/4.4.9
    Transfer-Encoding: chunked
    Content-Type: text/html; charset=utf-8

    9a2
    [Actual File data]

    Notice the "9a2" on the line above. This indicates this chunk is
    0x9a2 hexadecimal bytes long (2466 in decimal). If you open the file
    in a hex editor, you'll see 0x0D 0x0A after the chunk length
    number. Starting from the Carriage Return/Linefeed (0x0D 0x0A) sequence,
    go to the section of the file 0x9a2 bytes further in the file.'''
    b = '''
    When you get to the next location, you'll see the 0x0D 0x0A sequence
    followed by a new chunk length and another 0x0D 0x0A sequence.
    Using your hex editor, you should delete this sequence of bytes.
    In this instance, you would remove 0x0D 0x0A 0x39 0x61 0x32 0x0D 0x0A.
    (0x39 0x61 0x32 is character codes for '9a2'). Continue until all chunks
    have been properly joined.

    Files may be compressed with gzip encoding to reduce file transfer time.
    GZIP compress can be recognised with the following header:

    HTTP/1.1 200 OK
    Date: Tue, 26 Jun 2012 23:36:39 GMT
    Server: Apache/2.2.14 (Ubuntu)
    Accept-Ranges: bytes
    Vary: Accept-Encoding
    Content-Encoding: gzip
    Content-Length: 439
    Content-Type: text/html
    '''
    c = '''
    The HTTP header is terminated by a blank line. The body of
    the HTTP response follows the header. Following the header will
    be either the gzipped body or the first block for chunked encoding.
    Gzip encoding begins with a 0x1F 0x8D sequence. '''
    print(a)
    response = input('\nPress <Enter> for More: ')
    print(b)
    response = input('\nPress <Enter> for More: ')
    print(c)

def help_inputfiles():
    '''Describe using Spondulas to parse standalone HTML files.'''
    a = '''
    Spondulas can be used to parse standalone HTML files. You may encounter
    this if someone e-mails an HTML page with an embedded form as an
    attachment or the input of monitor mode. Simply start Spondulas and supply
    the -i inputfile argument.

    The presence of an -i argument disables the page retrieval functions.
    '''
    print(a)

def help_monitor_mode():
    '''Describe using monitor_mode to monitor websites.'''
    a = '''
    ***********
    * CAUTION *
    ***********

    Use caution when using monitor_mode. Using short time values for extended
    periods of time could be construed as a hostile action.

    Monitor mode is used to detect changes in DNS or HTML body content over
    time. The first request is stored in a timestamped output file and the
    body of the HTTP response is hashed with SHA1. The SHA1 hash is retained
    for comparison with the response to the next request. If the next
    response is identical to the last response, the time of request is printed
    to screen. If the response is different, the time stamp and has is printed
    to screen and the output is saved to a timestamped file. If you wish
    to process the changed file for links, you can use the input file mode.

    '''
    print(a)
    response = input('\nPress <Enter> for More: ')

def help_tor():
    '''Help for using TOR'''
    a = '''
    Spondulas supports using the TOR proxy to anonymize your web requests.
    It is advisable to hide your source IP when investigating malicious web
    pages since attackers will often review their system logs to identify
    visitors.

    Tor can be obtained: https://www.torproject.org/

    By default, TOR is configured to accept SOCKS5 proxy requests on
    TCP Port 9050. Spondulas can connect as a SOCKS5 proxy client.

    Some malicious websites block TOR exit nodes.
    '''
    print(a)

def open_investigation_file(filename):
    '''Open Investigation file to add the info'''
    global outputfile
    global cookie_array
    # If file doesn't exist, just add the first entries
    if (os.path.exists(filename) != 1):
        z = open(filename,'w')
        a = str(int(outputfile.partition('.')[0])) + '. ' +target_url + '\t(' + ip_address + ')\n'
        z.write(a)
        # If we have cookies, add them to the file
        if(len(cookie_array)):
            for i in range(0,len(cookie_array)):
                z.write('Cookie: '+cookie_array[i])
    else:
        z = open(filename,'r+')
        oldfile = []
        counter = 0

        # Load the file into an array so it can be accessed by index
        for i in z.readlines():
            oldfile.append(i)

        # If there is a second file without a referrer due to a user error
        if(len(referrer) == 0):
            counter = 0
            a = str(int(outputfile.partition('.')[0])) + '. ' + target_url + '\t(' + ip_address + ')\n'
            oldfile.insert(counter,a)
            if(len(cookie_array)):
                for n in range(0,len(cookie_array)):
                    counter += 1
                    oldfile.insert(counter,'Cookie: '+cookie_array[n])
            z.seek(0)
            for i in oldfile:
                z.write(i)
            z.close()
            return

        for i in range(0,len(oldfile)):
            # Counter should be current line + 1
            counter += 1
            # Capture information on Referrer
            if (( re.search(referrer,oldfile[i])) or (counter == len(oldfile))):
                # Capture the indent level so we can add one
                tabs = re.match('\t*',oldfile[i])
                if(tabs is not None):
                    tabs = tabs.group(0)
                else:
                    tabs = ''
                # Prepare current line to insert *somewhere*
                a = tabs+'\t'+str(int(outputfile.partition('.')[0])) + '. ' +target_url + '\t(' + ip_address + ')\n'
                # Increment counter to skip over cookies
                if ((counter < len(oldfile)) and (re.search('Cookie',oldfile[counter]))):
                    # The entry may have multiple cookies
                    while((counter < len(oldfile)) and (re.search('Cookie',oldfile[counter]))):
                        counter += 1

                # Insert line after the referrer + cookies
                oldfile.insert(counter,a)
                # Insert any cookies
                if(len(cookie_array)):
                    for n in range(0,len(cookie_array)):
                        counter += 1
                        oldfile.insert(counter,tabs+'\tCookie: '+cookie_array[n])
        # Write changes to the file
        z.seek(0)
        for i in oldfile:
            z.write(i)

    z.close()

def parse_results():
    '''Parse the output file for cookies, forms, etc.'''
    global autolog
    global decoded
    global results

    a = open(outputfile,'rb')
    b = a.read()
    a.close()

    b = dechunk(b)
    b = ungzip(b)
    b = demangle(b)

    if(decoded >0):
        offset = outputfile.find('.')
        decodedfilename = outputfile[0:offset]+'-decoded'+outputfile[offset:]
        decoded = open(decodedfilename,'wb')
        decoded.write(b)
        decoded.close()
        a = open(decodedfilename,'rb')
    else:
        a = open(outputfile,'rb')

    for line in a.readlines():
        get_response_redirects(line)
        get_response_cookies(line) # This works
        get_response_forms(line)   # This works
        get_response_address(line) # This works
        get_response_images(line)  # This works
        get_response_stylesheets(line) # This works
        get_response_external_scripts(line)
    a.close()

    # If autolog is selected, create an investigation file
    if(autolog):
        open_investigation_file(create_investigation_filename())

def post_processing():
    '''Processes HTML files for links'''
    if(os.stat(outputfile)[6] != 0):
        parse_results()
        create_report()
    else:
        print('\nNo data returned')
        os.remove(outputfile)

def retrieve_page():
    '''Sends the query to the target URL.'''
    global monitormode

    if(monitormode != 1):
        print('Query being sent')
        print('----------------')
        print(webrequest['query'])
        print('\nDo not be alarmed if the progam appears to "hang."')
        print('This is caused by keep-alive packets. A timeout exception')
        print('will be raised after '+str(timeout)+' seconds.')
        print('\nBirds away.....')
    r = ThreadClass()
    r.start()
    for i in range(1,timeout+15):
        if(monitormode != 1):
            print('.',end='')
            sys.stdout.flush()
        time.sleep(1)
        if(threading.active_count()==1):
            break

def main():
    '''Master program function'''
    get_options()
    if(len(inputfile)>0):
        inputfile_processing_mode() # input_processing_mode: Process a local html file
    elif(persistent):
        persistent_mode()
    elif(monitormode):
        monitor_mode()
    else:
        normal_mode() # Normal mode: download a network resource and process

#####################
# Processing Modes  #
#####################

def inputfile_processing_mode():
    '''The processes HTML files that have been e-mailed, etc'''
    global outputfile
    outputfile = inputfile
    get_link_file(outputfile)
    post_processing()

def monitor_mode():
    '''Monitor mode retrieves pages and intervals and monitors for changes'''
    global outputfile
    global total_seconds

    get_user_agent()
    get_target_url()
    if(get_request_type()):
        get_post_vars()
    get_referrer()
    get_cookies()
    webrequest['query'] = create_request()
    if(total_seconds == 0):
        timer_get_sleep_time()
    last_hash = ''
    last_ip = ''
    while 1:
        timestamp = timer_build_timestamp()
        outputfile = timestamp + '.txt'
        outputfile = outputfile.replace(':','-')
        retrieve_page()
        a = open(outputfile,'rb')
        b = a.read()
        a.close()
        first = b.find(bytes('\x0D\x0A\x0D\x0A','latin'))
        result = b[first:]
        new_hash = timer_get_sha(result)
        new_ip = hashlib.sha1(bytes(ip_address,'latin')).hexdigest()
        if((new_hash != last_hash)or(new_ip != last_ip)):
            print('\n'+timestamp+'\t'+new_hash)
            last_hash = new_hash
            last_ip = new_ip
        else:
            print(timestamp)
            os.unlink(outputfile)

        time.sleep(total_seconds)

def normal_mode():
    '''Normal mode retrieves and parses the file'''
    get_user_agent()
    get_target_url()
    if(get_request_type()):
        get_post_vars()
    get_referrer()
    get_cookies()
    get_output_file()
    get_link_file(outputfile)
    webrequest['query'] = create_request()
    retrieve_page()
    post_processing()

def persistent_mode():
    '''Persistent Mode allows keepalive connection/ajax'''
    global request
    get_user_agent()
    get_target_url()
    if(get_request_type()):
        get_post_vars()
    get_referrer()
    get_cookies()
    webrequest['query'] = create_request()
    # Copy the target_url into the referrer field
    webrequest['referrer'] = webrequest['protocol'] +  \
        '://' + webrequest['host'] + webrequest['resource']
    old_host = webrequest['host']
    request = ''
    more_choices = 1
    while(more_choices):
        print('\nPlease enter the AJAX request:')
        webrequest['postvars'] = ''
        webrequest['content_length'] = ''
        if(get_request_type()):
            get_post_vars()
        get_target_url()
        webrequest['host'] = old_host
        temp_request = create_request()
        ajax.append(temp_request)
        answer = ''
        while(len(answer) != 1):
            answer = input('More [Y/N]? ')
            if(answer.lower() == 'n'):
                more_choices = 0
                break

    get_output_file()
    get_link_file(outputfile)
    retrieve_page()
    post_processing()

class ThreadClass(threading.Thread):
    '''Class used to make the actual webrequest. This allows threading'''
    def run(self):
        global ip_address
        o = open(outputfile,'wb')
        try:
            if (socksport):
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('localhost',socksport))
                s.settimeout(timeout)
                r = s.send(bytes('\x05\x01\x00',encoding='ascii'))
                b = s.recv(2)
                host = webrequest['host']

                if(SSL):
                    temp = '\x05\x01\x00\x03'+ chr(len(host)) + host +'\x01\xBB'
                    s.send(bytes(temp,'ascii'))
                    b = s.recv(14)
                else:
                    temp = '\x05\x01\x00\x03'+ chr(len(host)) + host +'\x00\x50'
                    s.send(bytes(temp,'ascii'))
                    b = s.recv(14)

            elif(SSL):
                a = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                a.connect((webrequest['host'],port))
                a.settimeout(timeout)
                s = ssl.wrap_socket(a)
            else:
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            	# If the connection times out too quickly to retrieve all data
            	# increase the timeout
                s.settimeout(timeout)
                s.connect((webrequest['host'],port))
            ip_address = socket.gethostbyname_ex(webrequest['host'])[2][0]
            print('IP address: '+ip_address)
            s.send(bytes(webrequest['query'],'ascii'))
            for i in ajax:
                s.send(bytes('\n'+i,'ascii'))

            while 1:
                server_response = s.recv(4096)
                if(len(server_response) == 0): raise socket.timeout

                o.write(server_response)
        except socket.gaierror:
            print('\nUnable to find target server')
            s.close()
            o.flush()
            o.close()
        except socket.herror:
            print('Unable to find target server')
            s.close()
            o.close()
        except ssl.SSLError:
            pass
            #print('Timeout reached')
        except socket.timeout:
            s.close()
            o.close()
        else:
            s.close()
            o.flush()
            o.close()

def timer_build_timestamp():
    '''Creates Timestamp for request in monitor mode. Also used to create outputfilename.'''
    a = time.localtime()
    b = str(a.tm_year)+'-'+'{:02d}'.format(a.tm_mon)+'-'
    b += '{:02d}'.format(a.tm_mday)+'_'+'{:02d}'.format(a.tm_hour)
    b += ':'+'{:02d}'.format(a.tm_min)+':'+'{:02d}'.format(a.tm_sec)
    return b

def timer_calculate():
    '''Calculates sleep time for monitor mode.'''
    global total_seconds
    global time_calculated
    total_seconds = (days * 86400) + (hours * 3600) + (minutes * 60) + seconds
    print('Time: '+str(total_seconds)+' seconds')
    time_calculated = 1

def timer_days():
    '''Allows entry of days to sleep in monitor mode'''
    global days
    print('\n\nMaximum Days: 25\n')
    days = input('Days to sleep: ')
    days = int(days)
    if(days > 25):
        days = 25

def timer_get_sha(a):
    '''Returns the SHA1 signature of the body of the web page and IP used in monitor mode.'''
    return hashlib.sha1(a).hexdigest()

def timer_get_sleep_time():
    '''Allows input of sleep time for monitor mode.'''
    timer_menu_get_sleep_time() 

def timer_hours():
    '''Allows entry of hours to sleep in monitor mode'''
    global hours
    hours = input('Hours to sleep: ')
    hours = int(hours)

def timer_menu_get_sleep_time():
    '''Builds the menu to calculate sleep time for monitor mode.'''
    while (time_calculated < 1):
    
        print('Monitor Mode timer settings')
        print('---------------------------\n\n')
        print('************')
        print('* CAUTION! *')
        print('************')
        print('Use caution when setting delays between checks.')
        print('You don\'t want to be accused of attacking the website.')
        print('\nDays should be less than 25')
        dispatch = [['Days\t\t\t'+str(days),timer_days],
                    ['Hours\t\t'+str(hours),timer_hours],
                    ['Minutes\t\t'+str(minutes),timer_minutes],
                    ['Seconds\t\t'+str(seconds),timer_seconds],
                    ['Calculate Sleep and Continue',timer_calculate]]

        get_choices(dispatch,'Select: ')

def timer_minutes():
    '''Allows entry of minutes to sleep in monitor mode'''
    global minutes
    minutes = input('Minutes to sleep: ')
    minutes = int(minutes)

def timer_seconds():
    '''Allows entry of seconds to sleep in monitor mode'''
    global seconds
    seconds = input('Seconds to sleep: ')
    seconds = int(seconds)

def ungzip(a):
    '''This function decodes gzipped pages'''
    global decoded
    data = bytes()
    gzipped = a.find(bytes('Content-Encoding: gzip','latin'))
    if(gzipped > 0):
        decoded = 1
        first = a.find(bytes('\x1f\x8b','latin'))
        data += a[:first]
        b = a[first:]
        data += gzip.decompress(b)
    else:
        data = a

    return data

#########################
#   Program Entry Point #
#########################

if __name__ == '__main__':
    main()
