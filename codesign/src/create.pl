#!/usr/bin/perl

# Make these global so same stack can be overwritten each time
@stack = (  0x01, 0x00, 
			0x00, 0x01, 
			0x00, 0x02, 
			0x00, 0x03, 
			0x00, 0x04, 
			0x00, 0x05, 
			0x00, 0x06, 
			0x00, 0x07, 
			0x00, 0x08,
			0x00, 0x09, 
			0x00, 0x0A, 
			0x00, 0x0B, 
			0x00, 0x0C, 
			0x00, 0x0D, 
			0x00, 0x0E,
			0x00, 0x0F,
			0x00, 0x10, 
			0x10, 0x00, # Top 0x00000008
			0x00, 0x00, # Top 0x00000008
			0x00, 0x04, 
			0x00, 0x05, 
			0x00, 0x06, 
			0x00, 0x07, 
			0x00, 0x08,
			0x00, 0x09, 
			0x00, 0x0A, 
			0x00, 0x0B, 
			0x00, 0x0C, 
			0x00, 0x0D, 
			0x00, 0x0E,
			0x00, 0x08,
			0x00, 0x00
			 );
$count = 1;
$top = ( 0x00, 0x01);

##############################################################
##############################################################

#############
## Label 1
#############
label(1);
write_begin();
jump(3);
jump_to_line(2);

#############
## Label 2
#############
label(2);
ret();
#############


#############
## Label 3
#############
label(3);
jump(2);
ret();
#############

write_slide(0x3, 0x1200);



##############################################################
##############################################################

sub break {
	print "FLUSH\n"; $count++;
}

sub comment {
	$cmt = shift;
	print "! $cmt\n"; $count++;
}
sub jump {
	$n = shift;
	print "JUMP $n\n"; $count++;
}
sub jump_to_line {
	$line = shift;
	$stack[9*2] = $line;
	$stack[(9*2)+1] = 0x00;
	write_topOfStack(0x09, 0x00);
	ret();
}

sub label {
	$n = shift;
	print "\@LABEL $n\n"; $count++;
}

sub print_x2n {
	$x = shift;
	$n = shift;
	while($count < $n) {
		print "$x\n"; $count++;
	}
}

sub pop_stack {
	write_topOfStack($_[0], $_[1]);
	print "RETURN\n"; $count++;
}

sub push_stack {
	print "JSR $_[0]\n"; $count++;
}

$z = 0;
sub write_fill {
	$num = $_[0];
	while($count < $num-1) { pop_stack($num, 0x00); }
	$z++;
}

sub write2 {
	$to = shift;
	$from = shift;
	# overwrite top of stack
	write_topOfStack($from, 0x00);
	jump_to_line($to, 0x00);
	write_topOfStack($to, 0x00);
	# jump to line containing jsr to write line number to top of stack offset 
	jump_to_line(0x1)
}

sub write_begin {
	print "\@ORIGINATE\n";$count++;
	print "\@ANSWER\n";$count++;
	print "\@HANGUP\n";$count++;
}

sub write_topOfStack {
	$top[0] = shift;
	$top[1] = shift;
	reset_stack();
}

sub write_slide {
	$what = shift;
	$where = shift;
	for($i = 0; $i < $where; $i++) {
		print "JSR $what\n";$count++;
	}
}

sub write_checks {
	for ($i = 0; $i < 128; $i++) {
		print "IFTRIES $i\n";$count++;
		print "JUMP $i\n";$count++;
	}
}

sub ret {
	print "RETURN\n";$count++;
}

#sub clear_stack {
#	print "WRITE ^27AAA\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\n";
#	$count++;
#}

sub reset_stack {	
       ($s1, $s2) = sprintf("\\x%02x\\x%02x", $stack[0], $stack[1]);
       ($s3, $s4) = sprintf("\\x%02x\\x%02x", $stack[2], $stack[3]);
       ($s5, $s6) = sprintf("\\x%02x\\x%02x", $stack[4], $stack[5]);
       ($s7, $s8) = sprintf("\\x%02x\\x%02x", $stack[6], $stack[7]);
       ($s9, $s10) = sprintf("\\x%02x\\x%02x", $stack[8], $stack[9]);
       ($s11, $s12) = sprintf("\\x%02x\\x%02x", $stack[10], $stack[11]);
       ($s13, $s14) = sprintf("\\x%02x\\x%02x", $stack[12], $stack[13]);
       ($s15, $s16) = sprintf("\\x%02x\\x%02x", $stack[14], $stack[15]);
       ($s17, $s18) = sprintf("\\x%02x\\x%02x", $stack[16], $stack[17]);
       ($s19, $s20) = sprintf("\\x%02x\\x%02x", $stack[18], $stack[19]);
       ($s21, $s22) = sprintf("\\x%02x\\x%02x", $stack[20], $stack[21]);
       ($s23, $s24) = sprintf("\\x%02x\\x%02x", $stack[22], $stack[23]);
       ($s25, $s26) = sprintf("\\x%02x\\x%02x", $stack[24], $stack[25]);
       ($s27, $s28) = sprintf("\\x%02x\\x%02x", $stack[26], $stack[27]);
       ($s29, $s30) = sprintf("\\x%02x\\x%02x", $stack[28], $stack[29]);
       ($s31, $s32) = sprintf("\\x%02x\\x%02x", $stack[30], $stack[31]);
       ($s33, $s34) = sprintf("\\x%02x\\x%02x", $stack[32], $stack[33]);
       ($s35, $s36) = sprintf("\\x%02x\\x%02x", $top[0]);
       ($s37, $s38) = sprintf("\\x%02x\\x%02x", $top[1]);
       ($s39, $s40) = sprintf("\\x%02x\\x%02x", $top[0], $top[1]);
          #s1    s2     s3     s4       s5        s6        s7       s8      s9       s10      s11      s12      s13      s14     s15      s16      s??      top?
#$s1$s2 $s3$s4 $s5$s6 $s7$s8 $s9$s10 $s11$s12 $s13$s14$ s15$s16 $s17$s18 $s19$s20 $s21$s22 $s23$s24 $s25$s26 $s27$s28 $s29$s30 $s31$s32 $s33$s34 $s35$s36 $s37$s38
    	print "WRITE ^27AAA$s1$s2$s3$s4$s5$s6$s7$s8$s9$s10$s11$s12$s13$s14$s15$s16$s17$s18$s19$s20$s21$s22$s23$s24$s25$s26$s27$s28$s29$s30$s31$s32$s33$s34$s35$s36$s37$s38$s39$s40\n";
		$count++;
}

sub write_stack {
	$stack[0] = shift;
    $stack[1] = shift;
    $stack[2] = shift;
    $stack[3] = shift;
    $stack[4] = shift;
    $stack[5] = shift;
    $stack[6] = shift;
    $stack[7] = shift;
    $stack[8] = shift;
	reset_stack();
}

sub read_stack {
	
}


