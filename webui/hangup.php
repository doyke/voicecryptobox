<?php
#
# Write fifo to hangup call
#
$f = fopen("/tmp/aefifo_in", "w");
fwrite($f, "H");
fclose($f);  
?>
