use warnings;
use strict;

package XML::Compile::WSS::SecToken::X509v3;
use base 'XML::Compile::WSS::SecToken';

use Log::Report 'xml-compile-wss-sig';

use XML::Compile::WSS::Util qw/XTP10_X509v3 WSM10_BASE64/;

use MIME::Base64         qw/decode_base64 encode_base64/;
use Scalar::Util         qw/blessed/;
use Crypt::OpenSSL::X509 qw/FORMAT_ASN1 FORMAT_PEM/;
use Crypt::OpenSSL::RSA  ();

=chapter NAME
XML::Compile::WSS::SecToken::X509v3 - WSS Security Token X509v3 style

=chapter SYNOPSIS

  # Most verbose
  my $certfn = 'cert.pem';
  my $cert   = Crypt::OpenSSL::X509->new_from_file($certfn);
  my $token  = XML::Compile::WSS::SecToken::X509v3->new
    ( id          => 'some-wsu-id'
    , certificate => $cert
    );
  $wss->sigature(token => $token, ...);

  # Shortest
  $wss->signature(token => $cert, ...);

  # More syntax
  my $token = XML::Compile::WSS::SecToken->new
    ( type        => XTP10_X509v3
    , id          => 'some-wsu-id'
    , certificate => $cert
    );

  my $token = XML::Compile::WSS::SecToken::X509v3
    ->fromFile($cert_fn, format => FORMAT_ASN1);

=chapter DESCRIPTION
Use an X509 certificate as security token.

CPAN lists a few modules which wrap a X509 certificate, for the
moment only M<Crypt::OpenSSL::X509> is supported, patches for other
implementations are welcomed.

See F<docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0.pdf>

=chapter METHODS

=c_method new OPTIONS
Either the C<certificate> object or a C<cert_file> must be specified.
=default type XTP10_X509v3

=option  certificate CERTIFICATE
=default certificate C<undef>

=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{cert_file} and panic "removed in 1.07, use fromFile()";

    $args->{type} ||= XTP10_X509v3;
    $self->SUPER::init($args);

    my $cert;
    if($cert = $args->{certificate}) {}
    elsif(my $bin = $args->{binary})
         { $cert = Crypt::OpenSSL::X509->new_from_string($bin, FORMAT_ASN1) }
    else { error __x"certificate or binary required for X509 token" }

    blessed $cert && $cert->isa('Crypt::OpenSSL::X509')
        or error __x"X509 certificate object not supported (yet)";

    $self->{XCWSX_cert} = $cert;
    $self;
}

=c_method fromFile FILENAME, OPTIONS
[1.07] read the certificate from a file.  You can pass all OPTIONS provided
by M<new()> plus some specific parameters.

=option  format FORMAT_*
=default format FORMAT_PEM
The file format is not always auto-detected, so you may need to
provide it explicition.  The constants are exported by M<Crypt::OpenSSL::X509>
=cut

sub fromFile($%)
{   my ($class, $fn, %args) = @_;

    # openssl's error message are a poor
    -f $fn or error __x"key file {fn} does not exit", fn => $fn;

    my $format = delete $args{format} || FORMAT_PEM;
    my $cert   = eval { Crypt::OpenSSL::X509->new_from_file($fn, $format) };
    if($@)
    {   my $err = $@;
        $err    =~ s/\. at.*//;
        error __x"in file {file}: {err}" , file => $fn, err => $err;
    }

    $class->new(certificate => $cert, %args);
}

#------------------------
=section Attributes
=method certificate
=cut

sub certificate() {shift->{XCWSX_cert}}

#------------------------

sub asBinary()
{   my $self = shift;
    my $cert = $self->certificate;
    ( WSM10_BASE64, encode_base64($cert->as_string(FORMAT_ASN1),'') );
}

1;
