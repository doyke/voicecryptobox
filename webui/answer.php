<?php
#
# Write fifo to hangup call
#
$f = fopen("/tmp/aefifo_in", "w");
fwrite($f, "A");
fclose($f);  
?>
