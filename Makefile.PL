#!/usr/bin/env perl
use ExtUtils::MakeMaker;

use 5.008;

WriteMakefile
 ( NAME	 	=> 'XML::Compile::WSS::Signature'
 , VERSION	=> '0.91'

 , PREREQ_PM    =>
     { XML::Compile         => '1.29'
     , XML::Compile::Cache  => '0.992'
     , XML::Compile::SOAP   => '2.33'
     , XML::Compile::C14N   => '0.90'
     , XML::Compile::WSS    => '1.04'
     , Log::Report          => '0.92'

     , Encode               => 0
     , Digest               => 0
     , Test::More           => 0.54
     , MIME::Base64         => 0
     , File::Basename       => 0
     , File::Slurp          => 0

     , Crypt::OpenSSL::RSA  => 0
#    , Crypt::OpenSSL::CA   => 0
     , Crypt::OpenSSL::X509 => 0
     }
 , EXE_FILES    => []
 , AUTHOR       => 'Mark Overmeer'
 , ABSTRACT     => 'OASIS WSS Signatures'
 , LICENSE      => 'perl'
 );

### used by oodist during production of distribution
sub MY::postamble { <<'__POSTAMBLE' }

# for DIST
RAWDIR          = ../public_html/xml-compile-wss-signature/raw
DISTDIR         = ../public_html/xml-compile-wss-signature/source
LICENSE         = artistic

# for POD
FIRST_YEAR      = 2012
EMAIL           = perl@overmeer.net
EXTENDS         = ../XMLCompile:../XMLCache:../XMLWSS:../XMLC14N
WEBSITE         = http://perl.overmeer.net/xml-compile/
PODTAIL		= ../XML-shared-podtail
SKIP_LINKS	= XML::LibXML
__POSTAMBLE