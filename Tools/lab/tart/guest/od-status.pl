#!/usr/bin/perl
# SPDX-License-Identifier: MIT
# Reduce one `wgex status --json` read to the public on-demand evidence of ONDEMAND-ETH. No SSID, token or profile content.
use strict;
use warnings;
use JSON::PP;
my ($at, $pid, $started, $id, $discard) = @ARGV;
local $/;
my $raw = eval { decode_json(<STDIN>) } || {};
my $uuid = qr/^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$/;
sub word { my ($v, $re) = @_; return defined($v) && !ref($v) && $v =~ $re ? $v : undef; }
my $phase = word($raw->{phase}, qr/^(?:idle|preparing|configuring|active|reasserting|captiveWindow|stopping|failed)$/);
my $protection = word($raw->{protection}, qr/^(?:protected|blocked|unprotected|unknown|captiveWindow|unsupported)$/);
my $od = ref($raw->{onDemand}) eq 'HASH' ? $raw->{onDemand} : undef;
# The process identity this read belongs to: the pid and its start time, both measured around the read by gap-actions.sh.
my $start = word($started, qr/^[A-Za-z]{3} [A-Za-z]{3} [ 0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}$/);
my $why = word($discard, qr/^[A-Za-z]{1,40}$/);
if ($why || (defined($discard) && $discard ne '') || !defined($start) || $pid !~ /^[1-9][0-9]*$/) {
    # No usable identity: the read carries nothing and says why. The collector never counts it.
    print JSON::PP->new->canonical->encode({ at => 0 + $at, pid => 0, started => undef, phase => undef, protection => undef,
                                             onDemand => undef, discarded => $why || 'identityUnavailable' }), "\n";
    exit 0;
}
my %out = (at => 0 + $at, pid => 0 + $pid, started => $start, phase => $phase, protection => $protection, onDemand => undef);
if ($od) {
    my $armed = word($od->{armedProfileID}, $uuid);
    my $decision = ref($od->{decision}) eq 'HASH' ? $od->{decision} : {};
    $out{onDemand} = {
        armed => $armed ? JSON::PP::true : JSON::PP::false,
        armedIsProfile => $armed && defined($id) && uc($armed) eq uc($id) ? JSON::PP::true : JSON::PP::false,
        activated => $od->{activated} ? JSON::PP::true : JSON::PP::false,
        network => word($od->{network}, qr/^(?:none|ethernet|wifi)$/),
        decision => word($decision->{state}, qr/^(?:connect|disconnect|hold|paused)$/),
        reason => word($decision->{reason}, qr/^[A-Za-z]{1,40}$/),
        evaluated => defined($od->{evaluatedAtContinuous}) && !ref($od->{evaluatedAtContinuous}) ? JSON::PP::true : JSON::PP::false,
    };
}
print JSON::PP->new->canonical->encode(\%out), "\n";
