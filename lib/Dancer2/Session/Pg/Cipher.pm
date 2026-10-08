package Dancer2::Session::Pg::Cipher;

use strict;
use warnings;

use Moo::Role;
use Carp qw( croak );

our $VERSION = '0.001';

requires qw( cipher_id cipher_name key_bytes iv_bytes tag_bytes seal unseal );

# A plugged-in cipher is security-critical code this module did not write, so a
# candidate is exercised once when the engine is built rather than trusted until
# somebody's first login. Three ways one fails here: it describes itself
# impossibly, it cannot read back what it wrote, or it accepts a payload that has
# been altered -- the last being the whole reason only AEAD modes are allowed.
sub cipher_self_check {    ## no critic (Subroutines::ProhibitExcessComplexity) -- one linear list of guards; splitting it to satisfy a metric would hide the sequence
    my ($self) = @_;

    # Called as both a class and an instance method, so take the name either way
    # without the `ref $x || $x` idiom, which reads as a typo to half of Perl.
    my $class = ref $self ? ref $self : $self;

    for my $method (qw( cipher_id key_bytes iv_bytes tag_bytes )) {
        my $value = $self->$method;
        croak sprintf '%s: %s must be a positive integer (got %s)', $class, $method, ( defined $value ? "'$value'" : 'undef' )
          if !defined $value || $value !~ m/\A[0-9]+\z/msx || $value < 1;    ## no critic (RegularExpressions::ProhibitEnumeratedClasses) -- [0-9] is ASCII-only; \d and [[:digit:]] both match Unicode digits
    }

    croak sprintf '%s: cipher_id must be in 1..255 (got %d)', $class, $self->cipher_id
      if $self->cipher_id > 255;

    my $name = $self->cipher_name;
    croak "$class: cipher_name must be a non-empty string"
      if !defined $name || !length $name;

    my $key   = 'K' x $self->key_bytes;
    my $iv    = 'N' x $self->iv_bytes;
    my $plain = 'Dancer2::Session::Pg cipher self check';
    my $aad   = 'session-id-one';

    my ( $ciphertext, $tag ) = $self->seal( $key, $iv, $plain, $aad );

    croak "$class: seal returned no ciphertext"
      if !defined $ciphertext || !length $ciphertext;
    croak sprintf '%s: seal returned a %d-byte tag but tag_bytes says %d', $class,
      ( defined $tag ? length $tag : 0 ), $self->tag_bytes
      if !defined $tag || length $tag != $self->tag_bytes;

    my $back = eval { $self->unseal( $key, $iv, $ciphertext, $tag, $aad ) };
    croak "$class: unseal did not return what seal was given"
      if !defined $back || $back ne $plain;

    # The tag is the point, and the bar is ANY defined result rather than "not
    # the original plaintext". An unauthenticated stream mode hands back
    # *modified* plaintext for modified input, which is not a curiosity: it is
    # the attack. Flipping the bits under `"admin":0` to make it `"admin":1`
    # needs no key, and a session store that deserialises the result and then
    # trusts it has given the whole thing away. So a cipher that returns anything
    # at all for input it did not authenticate is refused here.
    for my $case ( [ 'ciphertext', 0 ], [ 'tag', 1 ] ) {
        my ( $part, $is_tag ) = @{$case};
        my @args = ( $ciphertext, $tag );
        my $i    = $is_tag ? 1 : 0;

        # 4-argument substr rather than the lvalue form, which Perl::Critic
        # dislikes and which reads worse here anyway.
        my $flipped = ( ord substr $args[$i], -1 ) ^ 0xFF;
        substr $args[$i], -1, 1, chr $flipped;

        my $forged = eval { $self->unseal( $key, $iv, @args, $aad ) };
        croak "$class: unseal returned data for a payload whose $part had been altered -- not an authenticated cipher"
          if defined $forged;
    }

    # LAST, because it is the narrower fault: a cipher that fails the checks
    # above does not authenticate at all, and saying so is more use than saying
    # it mishandled the additional data.
    #
    # A cipher that accepts the additional data and then ignores it is the
    # dangerous kind of wrong -- every round trip works, nothing looks amiss,
    # and the engine's binding of a payload to its session id silently does not
    # exist. That binding is what stops somebody with write access to the table
    # moving an administrator's sealed payload into their own row, so it is
    # tested rather than taken on trust.
    my $wrong_aad = eval { $self->unseal( $key, $iv, $ciphertext, $tag, 'session-id-two' ) };
    croak "$class: unseal IGNORED the additional authenticated data -- "
      . 'a payload sealed for one session id would open under another'
      if defined $wrong_aad;

    return 1;
}

1;

__END__

=encoding utf8

=for stopwords AEAD AES ChaCha DDL DSN GCM Kubernetes NIST OpenID Poly XHR crashloops dbh dbpass dbschema dbtable dbuser decrypt decryptable decrypted decrypts deserialise deserialising diagnosable dsn encryptions nonces plaintext preforked rollout serialiser tablespace Koivunalho Mikko

=head1 NAME

Dancer2::Session::Pg::Cipher - the authenticated-cipher contract for Dancer2::Session::Pg

=head1 VERSION

version 0.001

=head1 SYNOPSIS

    package My::Cipher::XChaCha20;

    use Moo;
    with 'Dancer2::Session::Pg::Cipher';

    use Crypt::AuthEnc::ChaCha20Poly1305 ();

    sub cipher_id   { return 200 }            # third-party range: 128..255
    sub cipher_name { return 'XChaCha20-Poly1305' }
    sub key_bytes   { return 32 }
    sub iv_bytes    { return 24 }             # a 24-byte nonce, unlike the core four
    sub tag_bytes   { return 16 }

    # $aad is authenticated but NOT encrypted, and must not be dropped: it is
    # what binds a sealed payload to the session id it belongs to.
    sub seal {
        my ( $self, $key, $iv, $plaintext, $aad ) = @_;
        return My::XChaCha::seal( $key, $iv, $aad, $plaintext );    # ( $ciphertext, $tag )
    }

    sub unseal {
        my ( $self, $key, $iv, $ciphertext, $tag, $aad ) = @_;
        return My::XChaCha::open( $key, $iv, $aad, $ciphertext, $tag );  # $plaintext or undef
    }

    # and then, in the application, as the alg of a slot
    #   encryption_keys:
    #     0: { key: "...", alg: "AES-256-GCM" }          # kept, read only
    #     1:
    #       key:    "..."
    #       alg:    "My::Cipher::XChaCha20"
    #       active: true

=head1 DESCRIPTION

L<Dancer2::Session::Pg> stores a cipher identifier in every payload it writes, so
the cipher a session was written with is a property of the row rather than of the
configuration. That is what makes a cipher replaceable: point C<alg> at a new one
and new sessions use it while existing rows stay readable until they expire.

This role is the contract such a cipher implements. Consume it with C<with>
rather than duck-typing the methods: that is how L</cipher_self_check> arrives,
and the engine refuses a cipher that does not provide it.

=head2 Only authenticated modes

A session frequently carries the credentials that prove who somebody is. A row
that has been altered in the database must B<fail to decrypt>, not deserialise
into a structure the application then trusts, so every cipher here produces a
tag and verifies it. L</cipher_self_check> tests exactly that, by flipping a bit
and insisting the result is refused.

=head2 Cipher ids are permanent

The id is one byte in every stored payload. Changing a cipher's id makes rows
written under the old one unreadable, which logs those users out.

    1 .. 127      reserved for ciphers shipped with Dancer2::Session::Pg
    128 .. 255    third-party range

The engine croaks at construction if two readable ciphers claim one id, so a
collision is a startup failure rather than a payload that decrypts as the wrong
thing. Within the third-party range a deployment owns its own collisions.

=head2 Your key length is your own business

A cipher declares the C<key_bytes> it needs, and the engine checks the key of the
slot your cipher sits in against B<that cipher and nothing else>. Other slots may
hold keys of other lengths; it does not concern you.

So there is no equal-key-length restriction to design around. A deployment can
rotate from a 16-byte cipher to a 32-byte one in a single step by giving the new
pair a slot of its own, which is what L<Dancer2::Session::Pg/Changing the key
length> describes and what the distribution's own test suite exercises.

What you must not do is assume anything about the key beyond its length. One
engine may hold several keys, a given row names the slot that sealed it, and your
C<seal> and C<unseal> are handed the key for that slot and never asked to choose.

=head1 REQUIRED METHODS

=head2 cipher_id

An integer in C<1 .. 255>, written into every payload. Permanent; see above.

=head2 cipher_name

A short string for error messages and C<algorithms>. Not stored.

=head2 key_bytes, iv_bytes, tag_bytes

The exact lengths this cipher requires, as integers. The engine validates the
configured key against C<key_bytes>, draws C<iv_bytes> from
L<Crypt::PRNG|CryptX> for every write, and uses C<tag_bytes> to find the
boundaries when reading a row back, so all three must be constant for a given
C<cipher_id>.

=head2 seal

    my ( $ciphertext, $tag ) = $cipher->seal( $key, $iv, $plaintext, $aad );

Encrypts and authenticates. Must return the tag separately, and it must be
exactly C<tag_bytes> long.

C<$aad> is additional data that must be B<authenticated but not encrypted>. The
engine passes the payload header and the session id, which is what binds a
sealed session to the row it belongs to. Pass it to your AEAD primitive -- do not
drop it, and do not encrypt it.

=head2 unseal

    my $plaintext = $cipher->unseal( $key, $iv, $ciphertext, $tag, $aad );

Verifies and decrypts. On failure, return C<undef> or throw -- the engine treats
both as "this row is not readable" and the session then looks absent rather than
corrupt. Do not return unverified plaintext under any circumstances, and B<fail
when C<$aad> does not match> what C<seal> was given: a cipher that accepts the
additional data and then ignores it would let a payload sealed for one session id
open under another. L</cipher_self_check> tests exactly that.

=head1 PROVIDED METHODS

=head2 cipher_self_check

    $cipher->cipher_self_check;    # or croaks

Called by L<Dancer2::Session::Pg> when the engine is built, once for B<every>
configured slot's cipher -- including the retired ones kept only to read old
rows, since a cipher that cannot be trusted to read is no more use than one that
cannot be trusted to write. Checks that the declared lengths are plausible, that
a known plaintext survives a round trip, that the tag is the advertised length,
that altering either the ciphertext or the tag is refused, and that the
additional authenticated data is actually authenticated.

It costs microseconds per slot and it runs before the process serves anything.

=head1 SEE ALSO

=over 4

=item * L<Dancer2::Session::Pg>

=item * L<Dancer2::Session::Pg::Cipher::AESGCM>

=item * L<Dancer2::Session::Pg::Cipher::ChaCha20Poly1305>

=back

=head1 AUTHOR

Mikko Koivunalho <mikko.koivunalho@iki.fi>

=head1 LICENSE AND COPYRIGHT

This software is copyright (c) 2026 by Mikko Koivunalho.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
