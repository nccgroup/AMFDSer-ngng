#BurpJDSer-ng



A Burp Extender plugin, that will take deserialized AMF objects and encode them in XML using the [Xtream](http://xstream.codehaus.org/) library. Based on the original work of Khai Tran, all hail  https://blog.netspi.com/
AMFDSer-ngng also utilizes part of Kenneth Hill's Jmeter source code for custom AMF deserialization (https://github.com/steeltomato/jmeter-amf). And the  Xtream library (http://xstream.codehaus.org/)

Why? This release fixes a bug where serialization wasn't being performed properly. It also adds in the (proper) ability to use the scanner in conjunction with AMF.  

Basically, it will deserialize, modify, reserialize, send on and (only in the case of the scanner) deserialize any responses that look like AMF objects (to allow burp to flag any exception strings, etc.)

nb. XML entity flagged scan results are false positives, the XML burp enters will be executed locally, this is NOT indicative of a problem on the remote server.

##Usage

###1) java -classpath burp.jar;AMFDSer-ngng.jar;xstream-1.4.2.jar burp.StartBurp

cheers
