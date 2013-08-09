#!/usr/bin/env perl
# Check processing of KeyInfo structures.
use warnings;
use strict;

use lib '../XMLWSS/lib', 'lib';

use Log::Report mode => 2;
use Test::More  tests => 36;

use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;
$Data::Dumper::Sortkeys  = 1;

use File::Slurp              qw/write_file/;
use MIME::Base64             qw/encode_base64/;

use XML::LibXML              ();
use XML::Compile::WSS::Util  qw/:xtp10 :wsm10/;
use XML::Compile::Tester     qw/compare_xml/;

my $certfn    = 't/20cert.pem';
sub newdoc() { XML::LibXML::Document->new('1.0', 'UTF8') }


use_ok('XML::Compile::Cache');
use_ok('XML::Compile::WSS::KeyInfo');
use_ok('XML::Compile::WSS::Signature');

my $schema    = XML::Compile::Cache->new;
ok(defined $schema);

my $wss       = XML::Compile::WSS::Signature->new
  ( version => '1.1'
  , schema  => $schema
  , prepare => 'NONE'
  , token   => 'dummy'
  );
isa_ok($wss, 'XML::Compile::WSS');
isa_ok($wss, 'XML::Compile::WSS::Signature');

### save template

write_file 'dump/keyinfo/KeyInfo.templ'
  , $wss->schema->template(PERL => 'ds:KeyInfo');

write_file 'dump/keyinfo/KeyIdentifier.templ'
  , $wss->schema->template(PERL => 'wsse:KeyIdentifier');

write_file 'dump/keyinfo/SecurityTokenReference.templ'
  , $wss->schema->template(PERL => 'wsse:SecurityTokenReference');

write_file 'dump/keyinfo/Reference.templ'
  , $wss->schema->template(PERL => 'wsse:Reference');

write_file 'dump/keyinfo/BinarySecurityToken.templ'
  , $wss->schema->template(PERL => 'wsse:BinarySecurityToken');

write_file 'dump/security.templ'
  , $wss->schema->template(PERL => 'wsse:Security');

write_file 'dump/signature.templ'
  , $wss->schema->template(PERL => 'ds:Signature');

### top-level KeyInfo readers and writers

use_ok('XML::Compile::WSS::KeyInfo');
my $ki         = XML::Compile::WSS::KeyInfo->new;
isa_ok($ki, 'XML::Compile::WSS::KeyInfo');

my $ki_reader  = $schema->reader('ds:KeyInfo');
isa_ok($ki_reader, 'CODE', 'ki_reader');

my $ki_tokens  = $ki->getTokens($wss);
isa_ok($ki_tokens, 'CODE', 'ki_tokens');

my $ki_writer  = $schema->writer('ds:KeyInfo');
isa_ok($ki_writer, 'CODE', 'ki_writer');

my $sec_reader = $schema->reader('wsse:Security');
isa_ok($sec_reader, 'CODE', 'sec_reader');

### learn some tokens

use_ok('XML::Compile::WSS::SecToken::X509v3');
my $x509     =  XML::Compile::WSS::SecToken::X509v3->fromFile($certfn);
ok(defined $x509, 'created x509v3 token');

my @t = $ki->tokens;
cmp_ok(scalar @t, '==', 0);
$ki->addToken($x509);
@t    = $ki->tokens;
cmp_ok(scalar @t, '==', 1);
is($t[0], $x509);

my $x509fp = $x509->fingerprint;
ok(defined $x509fp, 'got fingerprint');
my $x509fp64 = encode_base64 $x509fp;

### SECTOKREF_KEYID

ok(1, 'testing SECTOKREF_KEYID');

my $keyinfo1 = <<__KEYINFO__;
<?xml version="1.0"?>
<ds:KeyInfo
   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
>
  <wsse:SecurityTokenReference>
    <wsse:KeyIdentifier
       EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
       ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1">$x509fp64</wsse:KeyIdentifier>
  </wsse:SecurityTokenReference>
</ds:KeyInfo>
__KEYINFO__

my $keyhash1 = $ki_reader->($keyinfo1);
#warn Dumper $keyhash1;

my @tokens = $ki_tokens->($keyhash1);
cmp_ok(scalar @tokens, '==', 1, 'found one token');
isa_ok($tokens[0], 'XML::Compile::WSS::SecToken');
is($tokens[0], $x509);

my $wr1   = $ki->builder($wss
  , type  => 'SECTOKREF_KEYID'
  , keyident_id  => 'my-first-id'
  , sectokref_id => 'another-id'
  );
my $doc1  = newdoc;
my $data1 = $wr1->($doc1, $x509, undef);
#warn Dumper $data1;
my $xml1  = $ki_writer->($doc1, $data1);

compare_xml($xml1->toString(1), <<'__XML');
<ds:KeyInfo
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <wsse:SecurityTokenReference wsu:Id="another-id">
    <wsse:KeyIdentifier
      wsu:Id="my-first-id"
      EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
      ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1">Qzg6QUU6QjE6MjU6RDI6RkI6Rjk6MjA6RUE6RUU6NTM6NUM6NEQ6Mzk6OUU6MjQ6MDA6N0E6ODI6
RjI=
    </wsse:KeyIdentifier>
   </wsse:SecurityTokenReference>
</ds:KeyInfo>
__XML


### SECTOKREF_URI

ok(1, 'testing SECTOKREF_URI');
my $keyinfo2 = <<__KEYINFO__;
<?xml version="1.0"?>
<ds:KeyInfo Id="KI-7C1FF62FE1E419416813626762777505"
   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <wsse:SecurityTokenReference
     wsu:Id="STR-7C1FF62FE1E419416813626762777506">
    <wsse:Reference
       URI="#X509-7C1FF62FE1E419416813626762777504"
       ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
  </wsse:SecurityTokenReference>
</ds:KeyInfo>
__KEYINFO__

my $keyhash2 = $ki_reader->($keyinfo2);
#warn Dumper $keyhash2;

my $security = <<'__SECURITY';
<?xml version="1.0"?>
<wsse:Security
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <wsse:BinarySecurityToken
     EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
     ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
     wsu:Id="X509-7C1FF62FE1E419416813626762777504">MIIBvDCCAWqgAwIBAgIQ9bRpmRnJApVMfyrI8qph0jAJBgUrDgMCHQUAMBYxFDASBgNVBAMTC1Jvb3QgQWdlbmN5MB4XDTA4MDgyMDIwMTQ0M1oXDTM5MTIzMTIzNTk1OVowHzEdMBsGA1UEAxMUV1NFMlF1aWNrU3RhcnRDbGllbnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANJElGegKWGyIFAkCwqpX7NNjGHbOxS+5QHPPFZHFHD7LCJk46WiDehkIqhqNbV7hozJp5ml1aHDBmqdg4GqdkxgHQsdAzBnUkOUBlITPtKs+5n9HC5Qbi+kJKEWjcqzrvpNklSQUD4VPRxkGpGUJ1IFS+KO518GxRBOjc5UhL01AgMBAAGjSzBJMEcGA1UdAQRAMD6AEBLkCS0GHR1PAI1hIdwWZGOhGDAWMRQwEgYDVQQDEwtSb290IEFnZW5jeYIQBjdsAKoAZIoRz7jUqlw19DAJBgUrDgMCHQUAA0EAHNLqfHp6L1TBNjWf1e+Gz10UGnF8boh3SRBh5NXA0XLMl+abcFBIHXfXtfNW/C6Y1OG7NwS1GVRHQwNoakDNgQ==</wsse:BinarySecurityToken>
</wsse:Security>
__SECURITY

my $sec2    = $sec_reader->($security);
#warn Dumper $sec2;

my @tokens2 = $ki_tokens->($keyhash2, $sec2);
cmp_ok(scalar @tokens2, '==', 1, 'found one token');
isa_ok($tokens2[0], 'XML::Compile::WSS::SecToken::X509v3');
@t = $ki->tokens;
cmp_ok(scalar @t, '==', 2);

my $wr2   = $ki->builder($wss, type => 'SECTOKREF_URI');
my $doc2  = newdoc;
my $sec2b = $doc2->createElement('top');
my $data2 = $wr2->($doc2, $x509, $sec2b);
#warn Dumper $data2;
my $xml2  = $ki_writer->($doc2, $data2);

compare_xml($xml2->toString(1), <<'__XML');
<ds:KeyInfo
   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <wsse:SecurityTokenReference>
    <wsse:Reference URI="abc"
       ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
  </wsse:SecurityTokenReference>
</ds:KeyInfo>
__XML

compare_xml($sec2b->toString(1), <<'__SEC', 'binsectoken');
<top>
  <wsse:BinarySecurityToken
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
   wsu:Id="abc"
   EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
   ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">MIICNjCCAZ+gAwIBAgIJAPCFsh4JQEyUMA0GCSqGSIb3DQEBBQUAMDQxCzAJBgNVBAYTAk5MMQ8w
DQYDVQQHDAZBcm5oZW0xFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTEyMTEwMjIyMDEwOFoXDTEz
MTEwMjIyMDEwOFowNDELMAkGA1UEBhMCTkwxDzANBgNVBAcMBkFybmhlbTEUMBIGA1UEAwwLZXhh
bXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPLWMEhImMNpRTqMns6rADVhu8Yy
xBpLjh75nOsAj1aIWVM/Oi7pPwjCsMMyZV4iXGhT2WxmE9EmHBwgIqBn90qhbC7G3HwAvsTUAv27
phPco+u7tfhXmT1jG2NIWf0l/1SqDqXPUDecAz1xjTCYvMjCwm1dtsZDpmiUZVgCoR6XAgMBAAGj
UDBOMB0GA1UdDgQWBBRvhcWDNhXGhIj34sLkTAHvAT2qNTAfBgNVHSMEGDAWgBRvhcWDNhXGhIj3
4sLkTAHvAT2qNTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAN+lDWtlhFSxqLAcqA7R
IIj0LqMCL0RYEs3rbAaUliee5lM6cOkxStx2wkAVY68yBBLNmEYJ10yt/BLg6LiDeA7UxZ4gj/om
Q6/OsNC7eQJsxGKedA34/JT0R/zAVrHFkQYWrPNSkRLxQuXYG3xGLbQ6WVGJ25Iw+iYGYnKQYoMk
</wsse:BinarySecurityToken>
</top>
__SEC

#### KEYNAME

ok(1, 'testing KEYNAME');
my $keyinfo3 = <<__KEYINFO__;
<ds:KeyInfo
   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
   Id="key3-read">
  <ds:KeyName>C=NL, L=Arnhem, CN=example.com</ds:KeyName>
</ds:KeyInfo>
__KEYINFO__

my $keyhash3 = $ki_reader->($keyinfo3);
#warn Dumper $keyhash3;
is($keyhash3->{Id}, 'key3-read');

my @tokens3 = $ki_tokens->($keyhash1);
cmp_ok(scalar @tokens3, '==', 1, 'found one token');
isa_ok($tokens3[0], 'XML::Compile::WSS::SecToken');
is($tokens3[0], $x509);
is($tokens3[0]->name, 'C=NL, L=Arnhem, CN=example.com');

my $wr3   = $ki->builder($wss, type => 'KEYNAME', keyinfo_id => 'key3');
my $doc3  = newdoc;
my $data3 = $wr3->($doc3, $x509, undef);
#warn Dumper $data3;
my $xml3  = $ki_writer->($doc3, $data3);

compare_xml($xml3->toString(1), <<'__XML');
<ds:KeyInfo
   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
   Id="key3">
  <ds:KeyName>C=NL, L=Arnhem, CN=example.com</ds:KeyName>
</ds:KeyInfo>
__XML
