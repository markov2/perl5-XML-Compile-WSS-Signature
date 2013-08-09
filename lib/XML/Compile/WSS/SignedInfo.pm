use warnings;
use strict;

package XML::Compile::WSS::SignedInfo;

use Log::Report 'xml-compile-wss-sig';

use Digest;
use XML::Compile::C14N;
use XML::Compile::WSS::Util  qw/DSIG_NS DSIG_MORE_NS DSIG_SHA1 WSU_NS/;
use XML::Compile::C14N::Util qw/:c14n/;

my @default_canon_ns = qw/ds wsu xenc SOAP-ENV/;

# There can only be one c14n rule active, because it would otherwise
# produce a prefix
my $c14n;

=chapter NAME
XML::Compile::WSS::SignedInfo - administrating a SignedInfo block

=chapter SYNOPSIS
  # Not for end-users
  my $sig = XML::Compile::WSS::Signature->new(signedinfo => HASH);
  my $si  = $sig->signedinfo;

=chapter DESCRIPTION
The administration and reading/writing for the SignedInfo structure.

=chapter METHODS

=section Constructors

=c_method new WSS, OPTIONS

=option  digest_method DIGEST
=default digest_method DSIG_SHA1
The algorithm used to sign the body digest, when sending.

The digest name is an ugly constant which has a nice C<DSIG_*> alias
defined in M<XML::Compile::WSS::Util>.
The digest is implemented via the M<Digest> module, and its plugins.

=option  canon_method CANON
=default canon_method C14N_EXC_NO_COMM
The algorithm to be used for canonicalization of some component.
These constants are pre-defined with nice C<C14N_*> names in
M<XML::Compile::C14N::Util>.

=option  prefix_list ARRAY
=default prefix_list [ds wsu xenc SOAP-ENV]
Used for canonicalization.

=requires wss M<XML::Compile::WSS> object
Optional when a c14n is provided.

=option  c14n M<XML::Compile::C14N> object
=default c14n <created internally>
=cut

sub new(@) { my $class = shift; (bless {}, $class)->init({@_}) }
sub init($)
{   my ($self, $args) = @_;
    $self->{XCWS_pref} = $args->{prefix_list} || \@default_canon_ns;
    my $wss    = $args->{wss};

    # Immediately try-out the configured digest method.
    my $digest = $self->{XCWS_dig}
               = $args->{digest_method} || DSIG_SHA1;
    try { $self->_get_digester($digest, undef) };
    panic "digest method $digest is not useable: $@" if $@;

    my $canon  = $self->{XCWS_can}
               = $args->{canon_method}  || C14N_EXC_NO_COMM;

    $self->{XCWS_c14n} = $args->{c14n} ||= $c14n
      ||= XML::Compile::C14N->new(for => $canon, schema => $wss->schema);

    $self;
}

=c_method fromConfig HASH|PAIRS
All OPTIONS for M<new()>
=cut

sub fromConfig(@)
{   my $class = shift;
    $class->new(@_==1 ? %{$_[0]} : @_);
}

#-----------------
=section Attributes

=method defaultDigestMethod
=method defaultCanonMethod
=method defaultPrefixList
=method c14n
=cut

sub defaultDigestMethod() { shift->{XCWS_dig}  }
sub defaultCanonMethod()  { shift->{XCWS_can}  }
sub defaultPrefixList()   { shift->{XCWS_pref} }
sub c14n()                { shift->{XCWS_c14n} }

#-----------------
=section Handlers

=method builder WSS, OPTIONS
Not for end-users.  Returns a CODE which will be called to produce the
data for a ds_SignedInfo block.  The OPTIONS can overrule the defaults
set by M<new()>
=cut

sub builder($%)
{   my ($self, $wss, %args) = @_;

    my $schema   = $wss->schema;
    my $digest   = $args{digest_method} || $self->defaultDigestMethod;
    my $canon    = $args{canon_method}  || $self->defaultCanonMethod;
    my $preflist = $args{prefix_list}   || $self->defaultPrefixList;

    my $canonic  = $self->_get_canonic($canon, @$preflist);
    $schema->prefixFor($canon);  # enforce inclusion of c14n namespace

    my $digester = $self->_get_digester($digest, $canonic);
    my $cleanup  = $self->_get_repair_xml($wss);

    my $infow    = $schema->writer('ds:SignedInfo');
    my $inclw    = $self->_canon_incl($wss);

    sub {
        my ($doc, $elems, $sign_method) = @_;

        my @refs;
        foreach (@$elems)
        {   my $node  = $cleanup->($_, qw/wsu SOAP-ENV/);
            my $value = $digester->($node);

            my $transform =
             +{ Algorithm => $canon
              , cho_any => [ +{$inclw->($doc, $preflist)} ]
              };

            my $id = $node->getAttribute('Id')  # for the Signatures
                  || $node->getAttributeNS(WSU_NS, 'Id');  # or else

            push @refs,
             +{ URI             => '#'.$id
              , ds_Transforms   => { ds_Transform => [$transform] }
              , ds_DigestValue  => $value
              , ds_DigestMethod => { Algorithm => $digest }
              };
        }

        my $canonical = +{Algorithm => $canon, $inclw->($doc, $preflist)};

        my $siginfo = $infow->($doc, 
         +{ ds_CanonicalizationMethod => $canonical
          , ds_Reference              => \@refs
          , ds_SignatureMethod        => { Algorithm => $sign_method }
          } );

        my $si_canon = $canonic->($cleanup->($siginfo, @$preflist));  # to sign
        ($siginfo, $si_canon);
    };
}

=subsection Digest
=cut

my $digest_algorithm;
BEGIN
{   my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
    # the digest algorithms can be distiguish by pure lowercase, no dash.
    $digest_algorithm = qr/^(?:\Q$signs\E|\Q$sigmns\E)([a-z0-9]+)$/;
}

sub _get_digester($$)
{   my ($self, $method, $canonic) = @_;
    $method =~ $digest_algorithm
        or error __x"digest {name} is not a correct constant", name => $method;
    my $algo = uc $1;

    sub {
        my $node   = shift;
        my $digest = try
          { Digest->new($algo)         # Digest objects cannot be reused
             ->add($canonic->($node))
             ->digest                  # becomes base64 via XML field type
          };
        $@ or return $digest;

        error __x"cannot use digest method {short}, constant {name}: {err}"
          , short => $algo, name => $method, err => $@->wasFatal;
    };
}

sub _digest_check($$)
{   my ($self, $wss) = @_;

    sub {
        my ($elem, $ref) = @_;
        my $transf    = $ref->{ds_Transforms}{ds_Transform}[0]; # only 1 transf
        my $preflist  = [];
        if(my $r = $transf->{cho_any})
        {   my ($inclns, $preflist) = %{$r->[0]};    # only 1 kv pair
            $preflist = $preflist->{PrefixList} || [];
        }
        my $canonmeth = $transf->{Algorithm}    || $self->defaultCanonMethod;
        my $digmeth   = $ref->{ds_DigestMethod}
                            ->{Algorithm}       || $self->defaultDigestMethod;

        my $canonic   = $self->_get_canonic($canonmeth, @$preflist);
        my $digester  = $self->_get_digester($digmeth, $canonic);
        $digester->($elem) eq $ref->{ds_DigestValue};
    };
}

=subsection Canonicalization
With "canonicalization" you apply a set of rules to translate an XML
structure into a standardized ("canonical") format.

XML offers freedom on where to put namespace declarations, blanks between
elements, order of attributes, and so on.  However, when you want to
sign an element, meaningless changes do change the result.  Canonical
format enforces a set of rules, and produces bytes.

The "Digital Signature v1" supports c14n.  DSIG version 2 uses c14n2...
which is not yet supported.
=cut

sub _get_canonic($@)
{   my ($self, $canon, @preflist) = @_;
    my $c14n = $self->c14n;

    sub
      { my $node = shift or return '';
        $c14n->normalize($canon, $node, prefix_list => \@preflist);
      };
}

# only the inclusiveNamespaces of the Canon, while that's an 'any'
sub _canon_incl($)
{   my ($self, $wss) = @_;
    my $schema  = $wss->schema;
    my $type    = $schema->findName('c14n:InclusiveNamespaces');
    my $inclw   = $schema->writer($type, include_namespaces => 0);
    my $prefix  = $schema->prefixed($type);

    sub {
        my ($doc, $preflist) = @_;
        ($type => $inclw->($doc, {PrefixList => $preflist}));
    };
}

# XML::Compile plays nasty tricks while constructing the XML tree,
# which break normalisation.  The only way around that -on the moment-
# is to reparse the XML produced :(
# The next can be slow and is ugly, Sorry.  MO

sub _get_repair_xml($)
{   my ($self, $wss) = @_;
    my $preftab = $wss->schema->byPrefixTable;
    my %preftab = map +($_ => $preftab->{$_}{uri}), keys %$preftab;

    sub {
        my ($xc_out_dom, @preflist) = @_;

        # only doc element does charsets correctly
        my $doc    = XML::LibXML::Document->new('1.0', 'UTF8');

        # building bottom up: be sure we have all namespaces which may be
        # declared later, on higher in the hierarchy.
        my $env    = $doc->createElement('Dummy');
        $env->setNamespace($preftab{$_}, $_)
            for keys %preftab;

        # reparse tree
        $env->addChild($xc_out_dom->cloneNode);
        my $fixed_dom = XML::LibXML->load_xml(string => $env->toString(0));
        my $new_out   = ($fixed_dom->documentElement->childNodes)[0];
        $doc->importNode($new_out);
        $new_out;
    };
}

my $checker;
sub checker($)
{   my ($self, $wss) = @_;

    sub {
        my ($info, $sec, $token)  = @_;

        $token
            or error __x"cannot collect token from response";

        # Check signature on SignedInfo
        my $canon    = $info->{ds_CanonicalizationMethod};
        my $preflist = $canon->{c14n_InclusiveNamespaces}{PrefixList};
        my $canonic  = $self->_get_canonic($canon->{Algorithm}, @$preflist);
        my $si_canon = $self->digester($canonic->($info->{_XML_NODE}));

        unless($checker)
        {   # We only create the checker once: at the first received
            # message.  We may need to invalidate it for reuse of this object.
            my $sig_meth = $info->{ds_SignatureMethod}{Algorithm};
my $token;
            $checker     = $self->_get_signer($sig_meth, $token);
        }
        $checker->check($si_canon, $info->{ds_SignatureValue}{_})
#           or error __x"signature on SignedInfo incorrect";
            or warning __x"signature on SignedInfo incorrect";

        # Check digest of the elements
        my %references;
        foreach my $ref (@{$info->{ds_Reference}})
        {   my $uri = $ref->{URI};
            $references{$uri} = $ref;
        }

        my $check = $self->elementsToCheck;
#use Data::Dumper;
#warn "FOUND: ", Dumper \%references, $info, $check;
        foreach my $id (sort keys %$check)
        {   my $node = $check->{$id};
            my $ref  = delete $references{"#$id"}
                or error __x"cannot find digest info for {elem}", elem => $id;
            $self->_digest_elem_check($node, $ref)
                or warning __x"digest info of {elem} is wrong", elem => $id;
        }
    };
}

1;
