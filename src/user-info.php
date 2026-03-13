<?php 
    $lHTMLControls = 'minlength="1" maxlength="20" required="required"';

	try{
    	switch ($_SESSION["security-level"]){
			default: // Default case: This code is insecure
    		case "0": // This code is insecure
				$lEnableHTMLControls = false;
    			$lFormMethod = "GET";
				$lEnableJavaScriptValidation = false;
				$lProtectAgainstMethodTampering = false;
				$lEncodeOutput = false;
				$lProtectAgainstPasswordLeakage = false;
				break;
    		
    		case "1": // This code is insecure
				$lEnableHTMLControls = true;
    			$lFormMethod = "GET";
				$lEnableJavaScriptValidation = true;
				$lProtectAgainstMethodTampering = false;
				$lEncodeOutput = false;
				$lProtectAgainstPasswordLeakage = false;
			break;
    		
			case "2":
			case "3":
			case "4":
    		case "5": // This code is fairly secure
				$lEnableHTMLControls = true;
    			$lFormMethod = "POST";
				$lEnableJavaScriptValidation = true;
				$lProtectAgainstMethodTampering = true;
				$lEncodeOutput = true;
				$lProtectAgainstPasswordLeakage = true;
			break;
    	}//end switch

    	$lFormSubmitted = false;
		if (isset($_POST["user-info-php-submit-button"]) || isset($_REQUEST["user-info-php-submit-button"])) {
			$lFormSubmitted = true;
		}// end if
		
		if ($lFormSubmitted){

			
			if ($_SESSION["security-level"] >= 2) {
				if (!isset($_POST["csrf_token"]) || $_POST["csrf_token"] !== $_SESSION["csrf_token"]) {
					die("CSRF Attack Detected! Action Blocked for Security.");
				}
			}

    		if ($lProtectAgainstMethodTampering) {
   				$lUserInfoSubmitButton = $_POST["user-info-php-submit-button"];
				$lUsername = $_POST["username"];
				$lPassword = $_POST["password"];
    		}else{
    			$lUserInfoSubmitButton = $_REQUEST["user-info-php-submit-button"];
				$lUsername = $_REQUEST["username"];
				$lPassword = $_REQUEST["password"];
    		}// end if $lProtectAgainstMethodTampering
		}// end if $lFormSubmitted

   	} catch (Exception $e) {
		echo $CustomErrorHandler->FormatError($e, $lQueryString);
   	}// end try;
?>

<script type="text/javascript">
	<?php 
	if($lEnableJavaScriptValidation){
		echo "var lValidateInput = \"TRUE\"" . PHP_EOL;
	}else{
		echo "var lValidateInput = \"FALSE\"" . PHP_EOL;
	}// end if
	?>
			
	function onSubmitOfForm(/*HTMLFormElement*/ theForm){
		try{
			var lUnsafeCharacters = /[\W]/g;

			if(lValidateInput == "TRUE"){
				if (theForm.username.value.length > 15){
						alert('Username too long. We dont want to allow too many characters.\n\nSomeone might have enough room to enter a hack attempt.');
						return false;
				}// end if
		
				if (theForm.username.value.search(lUnsafeCharacters) > -1){
						alert('Dangerous characters detected. We can\'t allow these. This all powerful blacklist will stop such attempts.\n\nMuch like padlocks, filtering cannot be defeated.\n\nBlacklisting is l33t like l33tspeak.');
						return false;
				}// end if
			}// end if(lValidateInput)
			
			return true;
		}catch(e){
			alert("Error: " + e.message);
		}// end catch
	}// end function onSubmitOfForm(/*HTMLFormElement*/ theForm)
	
</script>

<div class="page-title">User Lookup (SQL)</div>

<?php include_once __SITE_ROOT__.'/includes/back-button.inc';?>
<?php include_once __SITE_ROOT__.'/includes/hints/hints-menu-wrapper.inc'; ?>

<form 	action="./index.php?page=user-info.php"
		method="<?php echo $lFormMethod; ?>" 
		enctype="application/x-www-form-urlencoded"
		onsubmit="return onSubmitOfForm(this);"
>
	<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>" />

	<input type="hidden" name="page" value="user-info.php" />
	<table>
		<tr id="id-bad-cred-tr" style="display: none;">
			<td colspan="2" class="error-message">
				Authentication Error: Bad user name or password
			</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td colspan="2" class="form-header">Please enter username and password<br/> to view account details</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td class="label">Username</td>
			<td>
				<input type="text" name="username" size="20" autofocus="autofocus"
					<?php if ($lEnableHTMLControls) { echo $lHTMLControls; } ?>
				/>
			</td>
		</tr>
		<tr>
			<td class="label">Password</td>
			<td>
				<input type="password" name="password" size="20"
					<?php if ($lEnableHTMLControls) { echo $lHTMLControls; } ?>
				/>
			</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td colspan="2" style="text-align:center;">
				<input name="user-info-php-submit-button" class="button" type="submit" value="View Account Details" />
			</td>
		</tr>
	</table>
</form>

<?php
	if ($lFormSubmitted){
		try {
			$lQueryResult = $SQLQueryHandler->getUserAccount($lUsername, $lPassword);
    		
   			$lResultsFound = false;
   			$lRecordsFound = 0;
			if (isset($lQueryResult->num_rows) && $lQueryResult->num_rows > 0) {
				$lResultsFound = true;
				$lRecordsFound = $lQueryResult->num_rows;
			}//end if

			if($lEncodeOutput){
				$lUsername = $Encoder->encodeForHTML($lUsername);
			}

			echo '<div class="report-header">
					Results for &quot;<span style="color:#770000;">'
					.$lUsername.
					'</span>&quot;. '.$lRecordsFound.' records found.
				</div>';

			if ($lResultsFound){
			    while($row = $lQueryResult->fetch_object()){
					if (!$lEncodeOutput) {
						$lUsername = $row->username;
						$lFirstName = $row->firstname;
						$lLastName = $row->lastname;
					} else {
						$lUsername = $Encoder->encodeForHTML($row->username);
						$lFirstName = $Encoder->encodeForHTML($row->firstname);
						$lLastName = $Encoder->encodeForHTML($row->lastname);
					}
					
					echo "<br/>";
					echo "<span class=\"label\">First Name:&nbsp;</span><span>{$lFirstName}</span><br/>";
					echo "<span class=\"label\">Last Name:&nbsp;</span><span>{$lLastName}</span><br/>";
					echo "<span class=\"label\">Username:&nbsp;</span><span>{$lUsername}</span><br/>";
					echo "<br/>";
				}
			} else {
				echo '<script>document.getElementById("id-bad-cred-tr").style.display=""</script>';
			}
    	} catch (Exception $e) {
			echo $CustomErrorHandler->FormatError($e, "Error attempting to display user information");
       	}
	}
?>


