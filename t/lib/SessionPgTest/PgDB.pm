package SessionPgTest::PgDB;
use strict;
use warnings;
use English qw( -no_match_vars );

# A throwaway PostgreSQL database for the tests that need one, on a cluster that
# is already running. It is deliberately self-contained: a distribution headed
# for CPAN cannot need anything but its own prerequisites to run its own tests.
#
# Perl 5.12, as the module: no signatures, no s///r.
#
# Usage: provision returns a live handle and the database name, or nothing with
# $SessionPgTest::PgDB::REASON set, which a caller passes to skip_all.
#
# The database is created with `createdb` as the current OS user (PGHOST,
# PGPORT and PGUSER are honoured) and dropped at exit BY ITS EXACT NAME, after
# the handle is disconnected -- dropdb refuses a database that still has a
# session, and a test that leaks one leaves it behind for good.
# SESSION_PG_TEST_KEEP_DB=1 keeps it for inspection.

use DBI ();

our $REASON;
my @CLEANUP;

END { $_->() for @CLEANUP }

sub provision {
    undef $REASON;
    my $name = sprintf 'session_pg_test_%d_%d', $PID, int rand 1_000_000;

    if ( system( 'createdb', $name ) != 0 ) {
        $REASON = 'createdb failed: no reachable PostgreSQL cluster where this user may create databases';
        return;
    }

    my $dbh = DBI->connect( "dbi:Pg:dbname=$name", q{}, q{}, { AutoCommit => 1, RaiseError => 1, PrintError => 0 } );

    if ( $ENV{'SESSION_PG_TEST_KEEP_DB'} ) {
        push @CLEANUP, sub { warn "SessionPgTest::PgDB: database '$name' KEPT; drop it with: dropdb $name\n" };
    } else {
        push @CLEANUP, sub {
            eval { $dbh->disconnect if $dbh };
            system 'dropdb', '--if-exists', $name;
        };
    }
    return ( $dbh, $name );
}

1;
