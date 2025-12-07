use MIME::Base64;
use Nix::Config;
use Nix::Manifest;
use Nix::Store;
use Nix::Utils;
use strict;
use LWP::UserAgent;
use File::Temp qw(tempfile);
use JSON::PP;

sub stripPath {
    my ($x) = @_;
    $x =~ s/.*\///; $x
}

my $secretKey;
BEGIN {
	my $secretKeyFile = $ENV{'NIX_SECRET_KEY_FILE'};
	if (defined $secretKeyFile) {
		$secretKey = readFile $secretKeyFile;
		chomp $secretKey;
	}
}

# Parse upstream caches from environment variable
# Default to cache.nixos.org if NIX_UPSTREAM_CACHES is not set
my @upstreamCaches = ();
if (defined $ENV{'NIX_UPSTREAM_CACHES'} && $ENV{'NIX_UPSTREAM_CACHES'} ne '') {
    @upstreamCaches = split(/,/, $ENV{'NIX_UPSTREAM_CACHES'});
    # Trim whitespace from each URL
    @upstreamCaches = map { s/^\s+|\s+$//gr } @upstreamCaches;
} else {
    @upstreamCaches = ('https://cache.nixos.org');
}

# Create a user agent for fetching from upstream caches
my $ua = LWP::UserAgent->new(
    timeout => 120,
    agent => 'nix-serve-mirror/1.0',
);

# Function to parse a narinfo response into a hash
sub parseNarinfo {
    my ($content) = @_;
    my %info = ();

    foreach my $line (split(/\n/, $content)) {
        # Skip empty lines
        next if $line =~ /^\s*$/;

        # Handle multi-value fields like Sig
        if ($line =~ /^(\w+):\s*(.*)$/) {
            my ($key, $value) = ($1, $2);
            if (exists $info{$key}) {
                # Convert to array if not already
                if (ref($info{$key}) ne 'ARRAY') {
                    $info{$key} = [$info{$key}];
                }
                push @{$info{$key}}, $value;
            } else {
                $info{$key} = $value;
            }
        }
    }

    return \%info;
}

# Function to download and decompress a NAR file
# Returns the path to the decompressed NAR, or undef on failure
sub downloadAndDecompress {
    my ($url, $compression) = @_;

    # Create a temporary file for the download
    my ($download_fh, $download_path) = tempfile(SUFFIX => '.nar.tmp', UNLINK => 1);
    close $download_fh;

    # Download the file
    my $response = $ua->get($url, ':content_file' => $download_path);
    unless ($response->is_success) {
        unlink $download_path;
        return undef;
    }

    # If no compression, we're done
    if (!defined $compression || $compression eq 'none') {
        return $download_path;
    }

    # Otherwise, decompress to another temporary file
    my ($decompressed_fh, $decompressed_path) = tempfile(SUFFIX => '.nar', UNLINK => 1);
    close $decompressed_fh;

    my $decompress_cmd;
    if ($compression eq 'xz') {
        $decompress_cmd = "xz -d < '$download_path' > '$decompressed_path'";
    } elsif ($compression eq 'bzip2') {
        $decompress_cmd = "bzip2 -d < '$download_path' > '$decompressed_path'";
    } elsif ($compression eq 'gzip') {
        $decompress_cmd = "gzip -d < '$download_path' > '$decompressed_path'";
    } elsif ($compression eq 'zstd') {
        $decompress_cmd = "zstd -d < '$download_path' > '$decompressed_path'";
    } else {
        # Unknown compression format
        unlink $download_path;
        return undef;
    }

    system($decompress_cmd);
    unlink $download_path;

    if ($? != 0) {
        unlink $decompressed_path;
        return undef;
    }

    return $decompressed_path;
}

# Function to fetch a path from upstream caches and import it into the local store
# Returns the store path if successful, undef otherwise
sub fetchFromUpstream {
    my ($hashPart) = @_;

    foreach my $upstream (@upstreamCaches) {
        # Remove trailing slash if present
        $upstream =~ s/\/$//;

        # Fetch the narinfo file
        my $narinfo_url = "$upstream/$hashPart.narinfo";
        my $narinfo_response = $ua->get($narinfo_url);

        # If this upstream doesn't have it, try the next one
        next unless $narinfo_response->is_success;

        my $narinfo = parseNarinfo($narinfo_response->decoded_content);

        # We need at least StorePath and URL
        next unless defined $narinfo->{StorePath} && defined $narinfo->{URL};

        my $store_path = $narinfo->{StorePath};
        my $nar_url = "$upstream/" . $narinfo->{URL};
        my $compression = $narinfo->{Compression} // 'none';

        # Download and potentially decompress the NAR
        my $nar_path = downloadAndDecompress($nar_url, $compression);
        next unless defined $nar_path;

        # Import the NAR into the local store
        # We use nix-store --restore because --import expects a different format
        # The NAR needs to be piped to nix-store --restore <store-path>
        my $import_cmd = "nix-store --restore '$store_path' < '$nar_path' 2>&1";
        my $import_output = `$import_cmd`;
        my $import_status = $?;

        unlink $nar_path;

        # If import succeeded, return the store path
        if ($import_status == 0) {
            return $store_path;
        }

        # If import failed, try the next upstream
    }

    # None of the upstreams had the path, or all imports failed
    return undef;
}

my $app = sub {
    my $env = shift;
    my $path = $env->{PATH_INFO};
    my $store = Nix::Store->new();

    if ($path eq "/nix-cache-info") {
        return [200, ['Content-Type' => 'text/plain'], ["StoreDir: $Nix::Config::storeDir\nWantMassQuery: 1\nPriority: 30\n"]];
    }

    elsif ($path =~ /^\/([0-9a-z]+)\.narinfo$/) {
        my $hashPart = $1;
        my $storePath = $store->queryPathFromHashPart($hashPart);

        # If not found locally and upstreams are configured, try fetching from upstream
        unless ($storePath) {
            if (@upstreamCaches > 0) {
                $storePath = fetchFromUpstream($hashPart);
            }
            return [404, ['Content-Type' => 'text/plain'], ["No such path.\n"]] unless $storePath;
        }

        my ($deriver, $narHash, $time, $narSize, $refs, $sigs) = $store->queryPathInfo($storePath, 1) or die;
        $narHash =~ /^sha256:(.*)/ or die;
        my $narHash2 = $1;
        die unless length($narHash2) == 52;
        my $res =
            "StorePath: $storePath\n" .
            "URL: nar/$hashPart-$narHash2.nar\n" .
            "Compression: none\n" .
            "NarHash: $narHash\n" .
            "NarSize: $narSize\n";
        $res .= "References: " . join(" ", map { stripPath($_) } @$refs) . "\n"
            if scalar @$refs > 0;
        $res .= "Deriver: " . stripPath($deriver) . "\n" if defined $deriver;
        if (defined $secretKey) {
            my $fingerprint = fingerprintPath($storePath, $narHash, $narSize, $refs);
            my $sig = signString($secretKey, $fingerprint);
            $res .= "Sig: $sig\n";
        } elsif (defined $sigs) {
            $res .= join("", map { "Sig: $_\n" } @$sigs);
        }
        return [200, ['Content-Type' => 'text/x-nix-narinfo', 'Content-Length' => length($res)], [$res]];
    }

    elsif ($path =~ /^\/nar\/([0-9a-z]+)-([0-9a-z]+)\.nar$/) {
        my $hashPart = $1;
        my $expectedNarHash = $2;
        my $storePath = $store->queryPathFromHashPart($hashPart);

        # If not found locally and upstreams are configured, try fetching from upstream
        unless ($storePath) {
            if (@upstreamCaches > 0) {
                $storePath = fetchFromUpstream($hashPart);
            }
            return [404, ['Content-Type' => 'text/plain'], ["No such path.\n"]] unless $storePath;
        }

        my ($deriver, $narHash, $time, $narSize, $refs, $sigs) = $store->queryPathInfo($storePath, 1) or die;
        return [404, ['Content-Type' => 'text/plain'], ["Incorrect NAR hash. Maybe the path has been recreated.\n"]]
            unless $narHash eq "sha256:$expectedNarHash";
        my $fh = new IO::Handle;
        open $fh, "-|", "nix", "--extra-experimental-features", "nix-command", "store", "dump-path", "--", $storePath;
        return [200, ['Content-Type' => 'text/plain', 'Content-Length' => $narSize], $fh];
    }

    # FIXME: remove soon.
    elsif ($path =~ /^\/nar\/([0-9a-z]+)\.nar$/) {
        my $hashPart = $1;
        my $storePath = $store->queryPathFromHashPart($hashPart);

        # If not found locally and upstreams are configured, try fetching from upstream
        unless ($storePath) {
            if (@upstreamCaches > 0) {
                $storePath = fetchFromUpstream($hashPart);
            }
            return [404, ['Content-Type' => 'text/plain'], ["No such path.\n"]] unless $storePath;
        }

        my ($deriver, $narHash, $time, $narSize, $refs) = $store->queryPathInfo($storePath, 1) or die;
        my $fh = new IO::Handle;
        open $fh, "-|", "nix", "--extra-experimental-features", "nix-command", "store", "dump-path", "--", $storePath;
        return [200, ['Content-Type' => 'text/plain', 'Content-Length' => $narSize], $fh];
    }

    elsif ($path =~ /^\/log\/([0-9a-z]+-[0-9a-zA-Z\+\-\.\_\?\=]+)/) {
        my $storePath = "$Nix::Config::storeDir/$1";
        my $fh = new IO::Handle;
        open $fh, "-|", "nix", "--extra-experimental-features", "nix-command", "log", $storePath;
        return [200, ['Content-Type' => 'text/plain' ], $fh];
    }

    else {
        return [404, ['Content-Type' => 'text/plain'], ["File not found.\n"]];
    }
}