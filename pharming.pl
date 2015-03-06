#!/usr/bin/env perl

use strict;
use warnings;

use Carp;
use Data::Dumper;
use English qw( -no_match_vars );
use Env qw(USER);
use Getopt::Long;
use List::Util qw(first);
use Net::DNS;
use Readonly;
use Storable;
use Sys::Hostname;
use Sys::Syslog;
use utf8;
use feature 'unicode_strings';

our $VERSION = 0.1;

#  constants
my @host = split qw{\.}, hostname, 2;
Readonly my $STORABLE => '.pharming.storable';
Readonly my $HOSTNAME => $host[0];


my $show_all;
my $create;
my $server_add;
my $server_remove;
my $mail_add;
my $mail_remove;
my $domain_add;
my $domain_remove;
my $description;
my $run;

#  setting STDOUT to UTF-8
binmode STDOUT, ':encoding(UTF-8)';

GetOptions(
    'create'       => \$create,
    'show-all'     => \$show_all,
    'server-add=s' => \$server_add,
    'server-remove=s' => \$server_remove,
    'mail-add=s'   => \$mail_add,
    'mail-remove=s'   => \$mail_remove,
    'domain-add=s' => \$domain_add,
    'domain-remove=s' => \$domain_remove,
        'description=s'   => \$description,
    'run' => \$run,
);

#
# log function
#
sub log_ {
    openlog('pharming', 'ndelay,pid', 'LOG_LOCAL0');
    syslog('LOG_INFO', 'action:%s user:%s host:%s info:%s result:%s', @_);
    closelog();
}
sub log_check {
    openlog('pharming', 'ndelay,pid', 'LOG_LOCAL0');
    syslog('LOG_INFO', 'action:%s user:%s host:%s server:%s domain:%s addr:%s result:%s', @_);
    closelog();
}


#
# Create storable file
#
if ($create) {
    my %structure = ( is_running => 0 );

    store \%structure, $STORABLE or croak 'Error: not possible create file';
    log_('create',$USER,$HOSTNAME,'info','ok');

}

#  check file permissions
if (!defined $STORABLE || !-r $STORABLE) {
    croak 'Error: storable not found. Use --create to create it.';
}

#
# Show configuration
#
if ($show_all) {
    my $structure = retrieve( $STORABLE );
    print Dumper($structure) or croak 'Error: not possible show configuration';
    log_('show_all',$USER,$HOSTNAME,'info','ok');
}

#
# Add DNS server
#
if ($server_add) {
    my %server;
    $server{server} = $server_add;

    ## add description
    if (defined $description) { $server{description} = $description; }

    ## add ptr name
    my $dig = Net::DNS::Resolver->new;
    my $query = $dig->query($server_add, 'PTR');
    if ($query) {
        foreach my $rr ($query->answer) {
            next if ($rr->type ne 'PTR');
            $server{ptr} .= $rr->rdatastr;
        }
    }

    my $structure = retrieve( $STORABLE );
    push @{$structure->{servers}}, \%server;
    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('server_add',$USER,$HOSTNAME,$server_add,'ok');
}

#
# Remove DNS server
#
if ($server_remove) {
    my $structure = retrieve( $STORABLE );
    my @servers;

    foreach my $server (@{$structure->{servers}}) {
        if ($server->{server} ne $server_remove) {
            push @servers, $server;
        }
    }
    @{$structure->{servers}} = @servers;

    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('server_remove',$USER,$HOSTNAME,$server_remove,'ok');
}

#
# Add mail to alert
#
if ($mail_add) {
    my %mail;
    $mail{mail} = $mail_add;

    ## add description
    if (defined $description) { $mail{description} = $description; }

    my $structure = retrieve( $STORABLE );
    push @{$structure->{alerts}}, \%mail;
    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('mail_add',$USER,$HOSTNAME,$mail_add,'ok');
}

#
# Remove mail to alert
#
if ($mail_remove) {
    my $structure = retrieve( $STORABLE );
    my @alerts;

    foreach my $alert (@{$structure->{alerts}}) {
        if ($alert->{mail} ne $mail_remove) {
            push @alerts, $alert;
        }
    }
    @{$structure->{alerts}} = @alerts;

    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('mail_remove',$USER,$HOSTNAME,$mail_remove,'ok');
}

#
# Add domain to monitoring
#
if ($domain_add) {
    my %domain;
    $domain{domain} = $domain_add;

    ## add description
    if (defined $description) { $domain{description} = $description; }

    my $structure = retrieve( $STORABLE );
    push @{$structure->{domains}}, \%domain;
    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('domain_add',$USER,$HOSTNAME,$domain_add,'ok');
}

#
# Remove domain to monitoring
#
if ($domain_remove) {
    my $structure = retrieve( $STORABLE );
    my @domains;

    foreach my $domain (@{$structure->{domains}}) {
        if ($domain->{domain} ne $domain_remove) {
            push @domains, $domain;
        }
    }
    @{$structure->{domains}} = @domains;

    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('domain_remove',$USER,$HOSTNAME,$domain_remove,'ok');
}

#
# Run!
#
if ($run) {
    my $structure = retrieve( $STORABLE );

    # check config
    if ( ref($structure->{alerts}) ne 'ARRAY' || scalar @{$structure->{alerts}} == 0 ) {
        croak 'Error: no mails for alerts...'
    }
    if ( ref($structure->{servers}) ne 'ARRAY' || scalar @{$structure->{servers}} == 0 ) {
        croak 'Error: no servers for monitoring...'
    }
    if ( ref($structure->{domains}) ne 'ARRAY' || scalar @{$structure->{domains}} == 0 ) {
        croak 'Error: no domains for monitoring...'
    }

    # find authoritative nameservers and address
    foreach my $domain (@{$structure->{domains}}) {
        @{$domain->{ns}} = get_authoritative_nameservers($domain->{domain});
        @{$domain->{a}} = get_authoritative_record($domain->{domain},$domain->{ns});

        if ( scalar @{$domain->{a}} == 0 ) {
            $domain->{error} = 'no-authoritative-response';
        }
    }

    # check nameservers
    foreach my $server (@{$structure->{servers}}) {

        # for each domain
        foreach my $domain (@{$structure->{domains}}) {
            if ( defined $domain->{error}) {
                print(qq(-> run-check $USER $HOSTNAME $server->{server} $domain->{domain} error $domain->{error}\n));
                next;
            }

            my @results = get_recursive_record($domain->{domain},$server->{server});

            # compare results
            foreach my $addr (@results) {
                if ( first { $_ eq $addr } @{$domain->{a}} ) {
                    log_check('run-check',$USER,$HOSTNAME,$server->{server},$domain->{domain},$addr,'ok');
                    print(qq(run-check $USER $HOSTNAME $server->{server} $domain->{domain} $addr ok\n));
                } else {
                    print(qq(-> run-check $USER $HOSTNAME $server->{server} $domain->{domain} $addr nok\n));
                }
            }
        }
    }

    log_('run',$USER,$HOSTNAME,$run,'ok');
}

# Given a hostname, find the nameservers.  This may require lopping bits off
# the start and trying again, e.g. for foo.bar.example.com, we'll probably
# need to know the nameservers for example.com (unless bar.example.com is
# delegated)
sub get_authoritative_nameservers {
    my $search = shift;
    my @nameservers;

    my $resolver = Net::DNS::Resolver->new;
    while (!@nameservers && $search) {
        my $res = $resolver->query($search, 'NS');
        my $ok;
        if ($res) {
            foreach my $rr ($res->answer) {
                next if ($rr->type ne 'NS');
                push @nameservers, $rr->nsdname;
                $ok = 1;
            }
        }
        if ( ! $ok ) {
            $search =~ s/^[^.]+\.//;
        }
    }
    log_('get_authoritative_nameservers',$USER,$HOSTNAME,$search,"@nameservers");
    return @nameservers;
}


sub get_authoritative_record {
    my $domain = shift;
    my $nameservers = shift;
    my @results;

    my $resolver = Net::DNS::Resolver->new(
        nameservers => $nameservers,
        recurse     => 0,
        defnames    => 0,
        );

    my $res = $resolver->query($domain, 'A');
    if ($res->header->aa) {
        foreach my $rr ($res->answer) {
            next if ($rr->type ne 'A');
            push @results, $rr->address;
        }
    }
    log_('get_authoritative_record',$USER,$HOSTNAME,$domain,"@results");
    return @results;
}


sub get_recursive_record {
    my $domain = shift;
    my $nameserver = shift;
    my @results;

    my $resolver = Net::DNS::Resolver->new(
        nameservers => [ $nameserver ],
        recurse     => 0,
        defnames    => 0,
        );

    my $res = $resolver->query($domain, 'A');
    if ($res) {
        foreach my $rr ($res->answer) {
            next if ($rr->type ne 'A');
            push @results, $rr->address;
        }
    }
    log_('get_recursive_record',$USER,$HOSTNAME,$domain,"@results");
    return @results;
}
