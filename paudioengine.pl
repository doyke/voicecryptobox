#!/usr/bin/perl

my $out_pipe_name = '/tmp/aefifo_out';
my $in_pipe_name = '/tmp/aefifo_in';

# open up connection to engine
open(FIFO_IN, "> $in_pipe_name") || die "can't write $in_pipe_name: $!";
print FIFO_IN '!';
close(FIFO_IN);

# get response from engine
my $buffer = "";
my $cmdbuffer = "";
my $len = "";
my $n;

open(FIFO_OUT, "< $out_pipe_name") || die "can't read $out_pipe_name: $!";

while (true) {
# read the command
    $n = read(FIFO_OUT, $cmdbuffer, 1);
    
# read len
    read(FIFO_OUT, $len, 2);
	
    my @btmp = unpack('C*',$len);
    $len =  @btmp[0] * 256 +  @btmp[1];
    
# look for status update
    if ($cmdbuffer eq "S") {
	&handle_status();
    }
    elsif ($cmdbuffer eq "L") {
	&handle_peerlist();
    } elsif ($cmdbuffer eq "W") {
	&handle_badlink();
    } else {
	print "Unknown command";
# just skip this command for now
    read(FIFO_OUT, $buffer, $len);
    }
}

sub handle_badlink
{
	# read status contents ("like audioenge version 0.1 ready etc")
	read(FIFO_OUT, $buffer, $len);
	my @tmp = unpack('C*', $buffer);
	if (@tmp[0] == 1) {
	    print "Bad link\n";
	}
 
}

sub handle_status
{
	# read status contents ("like audioenge version 0.1 ready etc")
	read(FIFO_OUT, $buffer, $len);
	print "Status:\n";
	print $buffer;    
 
}

sub handle_peerlist 
{
	my $offset = 0;
	read(FIFO_OUT, $buffer, $len);
	
	my $orig_len = $len;
	print "Peer list:\n";
	while ($len > 0) {
	    my $res = index($buffer, "\0", $offset);
	    my $peer = substr($buffer, $offset, $res - $offset);
	    my $status = substr($buffer, $res + 1, 1);
	    my @tmp = unpack('C*', $status);
	    print $peer;
	    if (@tmp[0] == 1) {
		print " busy";
	    }
	    else {
		print " available";
	    }
	    print "\n";
	    $offset = $res + 2;
	    $len = $orig_len - $offset;
	}

}

# call someone (just example)
#open(FIFO_IN, "> $in_pipe_name") || die "can't write $in_pipe_name: $!";
#print FIFO_IN 'C someone';
#close(FIFO_IN);
