# CyberSentinel Zeek Local Configuration
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
redef LogAscii::use_json = T;
