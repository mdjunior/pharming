#!/usr/bin/env perl

use strict;
use warnings;

# core modules
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

# external modules
use Authen::SASL;
use Net::SSLeay;
use Net::SMTP::SSL;

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
my $notify;
my $smtp_server;
my $auth;
my $mail_remove;
my $domain_add;
my $domain_remove;
my $description;
my $run;
my $verbose;
my $help;

#  setting STDOUT to UTF-8
binmode STDOUT, ':encoding(UTF-8)';

GetOptions(
    'create'          => \$create,
    'show-all'        => \$show_all,
    'server-add=s'    => \$server_add,
    'server-remove=s' => \$server_remove,
    'mail-add=s'      => \$mail_add,
    'notify=s'        => \$notify,
    'smtp=s'          => \$smtp_server,
    'auth=s'          => \$auth,
    'mail-remove=s'   => \$mail_remove,
    'domain-add=s'    => \$domain_add,
    'domain-remove=s' => \$domain_remove,
    'description=s'   => \$description,
    'run'             => \$run,
    'verbose'         => \$verbose,
    'help'            => \$help,
);

#
# log function
#
my $log;

sub log_ {
    my @args = @_;
    openlog('pharming', 'ndelay,pid', 'LOG_LOCAL0');
    syslog('LOG_INFO', 'action:%s user:%s host:%s info:%s result:%s', @args);
    $log .= sprintf "action:%s user:%s host:%s info:%s result:%s\n", @args;
    closelog();
    return;
}

sub log_check {
    my @args = @_;
    openlog('pharming', 'ndelay,pid', 'LOG_LOCAL0');
    syslog('LOG_INFO',
        'action:%s user:%s host:%s server:%s domain:%s addr:%s result:%s',
        @args);
    $log
        .= sprintf
        "action:%s user:%s host:%s server:%s domain:%s addr:%s result:%s\n",
        @args;
    closelog();
    return;
}


#
# Show help
#
if ($help) {
    print q(
        pharming
            Simple tool for monitoring DNS Hijacking

        --help
            Show this help

        --create
            Create a database

        --show-all
            Show all information

        --server-add
            Add DNS server to monitoring (optional: --description "DNS description")

        --server-remove
            Remove DNS server to monitoring

        --domain-add
            Add domain to monitoring (optional: --description "Example home page")

        --domain-remove
            Remove domain to monitoring

        --mail-add
            Add mail to send alerts
            REQUIRED:   --notify nok or --notify ok
                        --smtp smtp.example.com
                        --auth 'john@example.com:pass' (ex: user:pass)

        --mail-remove john@example.com
            Remove mail from alerts

        --run
            Run! (optional: --verbose)
) or croak 'Error: not possible show help';

}

#
# Create storable file
#
if ($create) {
    my %structure = (is_running => 0);

    store \%structure, $STORABLE or croak 'Error: not possible create file';
    log_('create', $USER, $HOSTNAME, 'info', 'ok');

}

#  check file permissions
if (!defined $STORABLE || !-r $STORABLE) {
    croak 'Error: storable not found. Use --create to create it.';
}

#
# Show configuration
#
if ($show_all) {
    my $structure = retrieve($STORABLE);
    print Dumper($structure) or croak 'Error: not possible show configuration';
    log_('show_all', $USER, $HOSTNAME, 'info', 'ok');
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

    my $structure = retrieve($STORABLE);
    push @{$structure->{servers}}, \%server;
    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('server_add', $USER, $HOSTNAME, $server_add, 'ok');
}

#
# Remove DNS server
#
if ($server_remove) {
    my $structure = retrieve($STORABLE);
    my @servers;

    foreach my $server (@{$structure->{servers}}) {
        if ($server->{server} ne $server_remove) {
            push @servers, $server;
        }
    }
    @{$structure->{servers}} = @servers;

    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('server_remove', $USER, $HOSTNAME, $server_remove, 'ok');
}

#
# Add mail to alert
#
if ($mail_add) {
    my %mail;

    # check notify
    if (!defined $notify) {
        croak 'Error: --notify is mandatory';
    }
    $mail{notify} = $notify;

    # check smtp
    if (!defined $smtp_server) {
        croak 'Error: --smtp is mandatory';
    }
    $mail{smtp_server} = $smtp_server;

    # check auth
    if (!defined $auth) {
        croak 'Error: --auth is mandatory';
    }
    $mail{auth} = $auth;

    $mail{mail} = $mail_add;

    ## add description
    if (defined $description) { $mail{description} = $description; }

    my $structure = retrieve($STORABLE);
    push @{$structure->{mails}}, \%mail;
    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('mail_add', $USER, $HOSTNAME, $mail_add, 'ok');
}

#
# Remove mail to alert
#
if ($mail_remove) {
    my $structure = retrieve($STORABLE);
    my @mails;

    foreach my $mail (@{$structure->{mails}}) {
        if ($mail->{mail} ne $mail_remove) {
            push @mails, $mail;
        }
    }
    @{$structure->{mails}} = @mails;

    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('mail_remove', $USER, $HOSTNAME, $mail_remove, 'ok');
}

#
# Add domain to monitoring
#
if ($domain_add) {
    my %domain;
    $domain{domain} = $domain_add;

    ## add description
    if (defined $description) { $domain{description} = $description; }

    my $structure = retrieve($STORABLE);
    push @{$structure->{domains}}, \%domain;
    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('domain_add', $USER, $HOSTNAME, $domain_add, 'ok');
}

#
# Remove domain to monitoring
#
if ($domain_remove) {
    my $structure = retrieve($STORABLE);
    my @domains;

    foreach my $domain (@{$structure->{domains}}) {
        if ($domain->{domain} ne $domain_remove) {
            push @domains, $domain;
        }
    }
    @{$structure->{domains}} = @domains;

    store $structure, $STORABLE or croak 'Error: not possible save file';
    log_('domain_remove', $USER, $HOSTNAME, $domain_remove, 'ok');
}

#
# Run!
#
if ($run) {
    my $structure = retrieve($STORABLE);

    # check config
    if (ref($structure->{mails}) ne 'ARRAY'
        || scalar @{$structure->{mails}} == 0)
    {
        croak 'Error: no mails for alerts...';
    }
    if (ref($structure->{servers}) ne 'ARRAY'
        || scalar @{$structure->{servers}} == 0)
    {
        croak 'Error: no servers for monitoring...';
    }
    if (ref($structure->{domains}) ne 'ARRAY'
        || scalar @{$structure->{domains}} == 0)
    {
        croak 'Error: no domains for monitoring...';
    }
    log_('run-check-config', $USER, $HOSTNAME, $run, 'ok');

    # find authoritative nameservers and address
    foreach my $domain (@{$structure->{domains}}) {
        @{$domain->{ns}} = get_authoritative_nameservers($domain->{domain});
        @{$domain->{a}}
            = get_authoritative_record($domain->{domain}, $domain->{ns});

        if (scalar @{$domain->{a}} == 0) {
            $domain->{error} = 'no-authoritative-response';
        }
    }

    # check nameservers
    foreach my $server (@{$structure->{servers}}) {

        # for each domain
        foreach my $domain (@{$structure->{domains}}) {
            if (defined $domain->{error}) {
                log_check('run-check-domain', $USER, $HOSTNAME,
                    $server->{server}, $domain->{domain}, 'error',
                    $domain->{error});
                next;
            }

            my @results
                = get_recursive_record($domain->{domain}, $server->{server});

            # compare results
            foreach my $addr (@results) {

                # prepare to save alert
                my %alert = (
                    server   => $server->{server},
                    domain   => $domain->{domain},
                    expected => "@{$domain->{a}}",
                    result   => $addr->{address},
                    details  => $addr->{details},
                );

                my $status;
                if (first { $_ eq $addr->{address} } @{$domain->{a}}) {
                    $status = 'ok';
                }
                else {
                    $status = 'nok';
                }

                push @{$structure->{alerts}->{$status}}, \%alert;

                log_check('run-check-domain', $USER, $HOSTNAME,
                    $server->{server}, $domain->{domain}, $addr->{address},
                    $status);

                if ($verbose) {
                    print
                        qq(run-check-domain $USER $HOSTNAME $server->{server} $domain->{domain} $addr->{address} $status\n)
                        or croak 'Error: not possible print';
                }
            }
        }
        log_('run-check-nameserver', $USER, $HOSTNAME, $server->{server},
            'ok');
    }


    # send alerts
    foreach my $mail (@{$structure->{mails}}) {
        my $smtp;
        my $time = localtime time;

        # skip if there is no alerts
        if (ref($structure->{alerts}->{$mail->{notify}}) ne 'ARRAY') {
            log_('run-send-alert', $USER, $HOSTNAME, $mail->{mail}, 'skip');
            next;
        }

        $smtp = Net::SMTP::SSL->new(
            $mail->{smtp_server},
            Port  => 465,
            Debug => $verbose,
        );

        my ($user, $pass) = split qw{:}, $mail->{auth}, 2;
        $smtp->auth($user, $pass)
            or croak "Error: Could not authenticate in SMTP $user,$pass";

        $smtp->mail($mail->{mail});
        if ($smtp->to($mail->{mail})) {
            $smtp->data();
            $smtp->datasend("From: $USER\@$HOSTNAME\n");
            $smtp->datasend("To: $mail->{mail}\n");
            $smtp->datasend(
                "Subject: [PHARMING] Report for $mail->{notify} domains at $time\n"
            );
            $smtp->datasend("\n");
            $smtp->datasend(
                generate_report($structure->{alerts}->{$mail->{notify}}));
            $smtp->datasend("\n");
            $smtp->datasend("LOG\n");
            $smtp->datasend("$log\n");
            $smtp->dataend;
            $smtp->quit;
        }
        log_('run-send-alert', $USER, $HOSTNAME, $mail->{mail}, 'ok');
    }

    log_('run', $USER, $HOSTNAME, $run, 'ok');
}

#
# get_authoritative_nameservers receive a domain and returns authoritative DNS
#   in array
#
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
        if (!$ok) {
            $search =~ s/^[^.]+\.//smx;
        }
    }
    log_('get_authoritative_nameservers',
        $USER, $HOSTNAME, $search, "@nameservers");
    return @nameservers;
}

#
# get_authoritative_record receive a domain and a array of nameserver and
#   returns a array of records
#
sub get_authoritative_record {
    my $domain      = shift;
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
    log_('get_authoritative_record', $USER, $HOSTNAME, $domain, "@results");
    return @results;
}

#
# get_recursive_record receive a domain and a nameserver and returns a array of
#   hash with detailed data about response
#
sub get_recursive_record {
    my $domain     = shift;
    my $nameserver = shift;
    my @results;
    my @address;

    my $resolver = Net::DNS::Resolver->new(
        nameservers => [$nameserver],
        recurse     => 0,
        defnames    => 0,
    );

    my $res = $resolver->query($domain, 'A');
    my $time = localtime time;
    if ($res) {
        foreach my $rr ($res->answer) {
            next if ($rr->type ne 'A');
            my %result = (
                address => $rr->address,
                details => {
                    time     => $time,
                    ttl      => $rr->ttl,
                    owner    => $rr->name,
                    type     => $rr->type,
                    class    => $rr->class,
                    rdstring => $rr->rdstring,
                    id       => $res->header->id,
                    opcode   => $res->header->opcode,
                    rcode    => $res->header->rcode,
                    qr       => $res->header->qr,
                    aa       => $res->header->aa,
                    tc       => $res->header->tc,
                    rd       => $res->header->rd,
                    ra       => $res->header->ra,
                    z        => $res->header->z,
                    ad       => $res->header->ad,
                    cd       => $res->header->cd,
                },
            );
            push @address, $rr->address;
            push @results, \%result;
        }
    }
    log_('get_recursive_record', $USER, $HOSTNAME, $domain,
        "$nameserver->@address");
    return @results;
}

#
# generate_report receive a hash data and return a string with a report
#
sub generate_report {
    my $data = shift;
    my $report;

    foreach my $alert (@{$data}) {
        $report .= "-> $alert->{domain}\n";
        $report .= "\tSERVER: $alert->{server}\n";
        $report .= "\tEXPECTED: $alert->{expected}\n";
        $report .= "\tRESULT: $alert->{result}\n";
        $report .= "\tDETAILS: " . Dumper($alert->{details}) . "\n";
        $report .= "\n";
    }

    return $report;
}
