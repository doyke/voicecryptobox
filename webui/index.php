<!DOCTYPE html>
<html>
<!-- UI Demo for nsa-fix.com  	-->
<!-- (c) nsa-fix.com 		-->
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>NSA-Fix v0.2 alpha</title>
	<link rel="stylesheet" href="css/themes/default/jquery.mobile-1.4.2.min.css">
	<link rel="stylesheet" href="_assets/css/jqm-demos.css">
	<link rel="shortcut icon" href="favicon.ico">
	<script src="js/jquery.js"></script>
	<script src="_assets/js/index.js"></script>
	<script src="js/jquery.mobile-1.4.2.min.js"></script>

	<script>
	function call(target)
	{
		document.getElementById("callTarget").innerHTML = target;
		$.get( "call.php", { data: target } )
		.done(function( data ) {
		// alert( "Data Loaded: " + data );
		});
	}
	function answer()
	{
		$.get( "answer.php");
	}
	function hangup()
	{
		$.get( "hangup.php");
	}
	function get_status(status)
	{	
		$.get( "status.php", { data: status } )
		.done(function( data ) {
			document.getElementById("StatusDisplay").innerHTML = data;
		});
		 setTimeout(get_status, 1000);
	}
	function get_peers(status)
	{	
		$.get( "peerlist.php", { data: status } )
		.done(function( data ) {
			document.getElementById("PeerDisplay").innerHTML = data;
		});
		 setTimeout(get_status, 1000);
	}

	$(document).ready(function() {
	  // run the first time; all subsequent calls will take care of themselves
	  	setTimeout(get_status, 1000);
		setTimeout(get_peers, 1000);
	});
	</script>
	
</head>
<body>
<!-- Start of first page: #one -->
<div data-role="page" id="one">

	<div data-role="header">
		<h1>NSA-Fix 0.2 Alpha</h1>
	</div><!-- /header -->

	<div role="main" class="ui-content" >
		<center>
		<img src="NSA-Fix-Logo-80px.png">
		</center>
		<p>
		<center>

		
		<table width=90% border=0 bgcolor="#FFFFFF">
		<tr>
		<td width=50% valign=top ><div id="StatusDisplay"></div></td>
		<td><div id="PeerDisplay"></td></tr>
		</table>

		</center>
		<p>
		<a href="" class="ui-btn ui-shadow ui-corner-all" onclick="answer()">Answer</a></p>
		<a href="" class="ui-btn ui-shadow ui-corner-all" onclick="hangup()">Hangup</a></p>
		<p>
		<p>
		<center><h3 class="ui-bar ui-bar-a">Contact list</h3></center>
		<p>
		<form>
		<div class="ui-field-contain">
		    <select name="select-native-1" id="select-native-1">
			<option value="0" onclick="call('alpha-1')">Call alpha-1</option>
			<option value="1" onclick="call('alpha-2')">Call alpha-2</option>
			<option value="2" onclick="call('alpha-3')">Call alpha-3</option>
			<option value="3" onclick="call('alpha-4')">Call alpha-4</option>
			<option value="4" onclick="call('alpha-5')">Call alpha-5</option>
			<option value="5" onclick="call('bravo-1')">Call bravo-1</option>
		    </select>
		</div>
		</form>

		<p>
		<a href="#two" class="ui-btn ui-shadow ui-corner-all">Network information</a></p>
	</div><!-- /content -->

	<div data-role="footer" data-theme="a">
		<h4>&copy; www.nsa-fix.com</h4>
	</div><!-- /footer -->
</div><!-- /page one -->

<!-- Start of second page: #two -->
<div data-role="page" id="two" data-theme="a">

	<div data-role="header">
		<h1>Network information</h1>
	</div><!-- /header -->

	<div role="main" class="ui-content">
		<h2>Two</h2>
		<p>
		[Placeholder for network information]
		<p><a href="#one" data-direction="reverse" class="ui-btn ui-shadow ui-corner-all ui-btn-b">Back</a></p>
	</div><!-- /content -->

	<div data-role="footer">
		<h4>&copy; www.nsa-fix.com</h4>
	</div><!-- /footer -->
</div><!-- /page two -->

<!-- Start of second page: #three -->
<div data-role="page" id="three" data-theme="a">

	<div data-role="header">
		<h1>Call</h1>
	</div><!-- /header -->

	<div role="main" class="ui-content">
		<center>		
			<h2>Calling...</h2>
			<p>
			<div id="callTarget"></div>
		</center>

		<p><a href="#one" data-direction="reverse" class="ui-btn ui-shadow ui-corner-all ui-btn-b" onclick="hangup()">Hang up</a></p>
	</div><!-- /content -->

	<div data-role="footer">
		<h4>&copy; www.nsa-fix.com</h4>
	</div><!-- /footer -->
</div><!-- /page three -->


</body>
</html>
