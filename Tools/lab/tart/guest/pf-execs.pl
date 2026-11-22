#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# Endpoint Security exec JSON stays in a pipe. Only the Lab daemon's pf state-kill arguments survive.
use strict;
use warnings;
use JSON::PP;
# Process arguments can hold secrets, and JSON::PP's parse errors quote the input. Every failure therefore leaves as one fixed
# diagnostic with no input excerpt: on stderr, and in the optional file named by the second argument (the guest script's
# record, so it never stores raw stderr).
$SIG{__WARN__} = sub { };
my %FIXED = map { $_ => 1 } ('daemon PID required', 'invalid pf exec arguments', 'incomplete exec event', 'malformed exec event stream');
sub fail {
    my ($error, $file) = @_;
    my $text = defined($error) && !ref($error) && $error =~ /\A([^\n]*)\n\z/ && $FIXED{$1} ? $1 : 'exec filter failed';
    if (defined $file && open(my $out, '>', $file)) { print $out "pf-execs: $text\n"; close $out; }
    print STDERR "$text\n";
    exit 1;
}
my ($pid, $diagnostic) = @ARGV;
eval { run($pid); 1 } or fail($@, $diagnostic);

sub run {
    my ($pid) = @_;
    die "daemon PID required\n" unless defined($pid) && $pid =~ /^[1-9][0-9]*$/;
    my $json = JSON::PP->new;
    my $count = 0;
    my $observed = 0;
    # The observer is stopped by killing eslogger, which can cut its last event short. That cut-off tail (no newline) is the stop
    # itself and lies after every observed window, so it is dropped; a newline-terminated line that leaves an event incomplete is
    # a corrupt stream and fails. (JSON::PP's incr_text croaks once an event has started, so completeness is tracked here.)
    my ($pending, $terminated) = (0, 1);
    while (my $line = <STDIN>) {
        $terminated = $line =~ /\n\z/ ? 1 : 0;
        next unless $line =~ /\S/;
        my $event = eval { $json->incr_parse($line) };
        die "malformed exec event stream\n" if $@;
        $pending = defined($event) ? 0 : 1;
        next unless defined($event);
        die "malformed exec event stream\n" unless ref($event) eq 'HASH';
        my $exec = ref($event->{event}) eq 'HASH' && ref($event->{event}{exec}) eq 'HASH' ? $event->{event}{exec} : {};
        my $target = ref($exec->{target}) eq 'HASH' ? $exec->{target} : {};
        my $path = ref($target->{executable}) eq 'HASH' ? $target->{executable}{path} : undef;
        next unless defined($path) && !ref($path) && $path eq '/sbin/pfctl' && ($target->{ppid} // 0) == $pid;
        $observed++;
        my $args = $exec->{args};
        next unless ref($args) eq 'ARRAY';
        shift @$args if @$args && !ref($args->[0]) && ($args->[0] eq '/sbin/pfctl' || $args->[0] eq 'pfctl');
        next unless grep { !ref($_) && ($_ eq '-k' || $_ eq 'states' || $_ eq 'all') } @$args;
        # Keep unsafe/global attempts too: the evaluator rejects them, without copying arbitrary process arguments.
        my $safe = @$args <= 12 && !grep { ref($_) || !/^[A-Za-z0-9:._\/-]{1,64}$/ } @$args;
        die "invalid pf exec arguments\n" unless $safe && ++$count <= 60;
        print JSON::PP->new->canonical->encode({pid => 0 + $pid, arguments => $args}), "\n";
    }
    die "incomplete exec event\n" if $pending && $terminated;
    # The positive control: how many pfctl children of the daemon the observer saw at all (its own canary polls included). A run
    # with no state kill is valid, since the daemon kills states only on blocking entry, but only when the observer demonstrably saw.
    print JSON::PP->new->canonical->encode({pid => 0 + $pid, daemonPfctlExecs => $observed}), "\n";
}
