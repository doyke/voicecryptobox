<?php
$DATA = $_GET['data'];

# echo "Call-$DATA";
#
# Write fifo to initiate call
#
$f = fopen("/tmp/aefifo_in", "w");
fwrite($f, "C $DATA");
fclose($f);  
?>
