<?php

if(!empty($_POST) && ($u_=$_POST['nkz']) && ($p_=$_POST['pass'])) {
	$outDir='.';
	$u_=preg_replace('/[^a-z0-9]+/i','',$u_);
	list($p,$u)=array_map('escapeshellarg',array($p_,$u_));
	$outFile=$outDir.'/'.$u_.'.pKey.pem';
	#header("x-out: $outFile");
	if(file_exists($outFile)) {
		$o_class='info';
		$o_text='Der Private Schlüssel wurde bereits erfolgreich entschlüsselt.';
	} else {
		
		$tmp=tempnam(sys_get_temp_dir(),'decr');
		$cmd = "./decrypt-private-key $u $p>$tmp";
		#header("x-tmp: $tmp");
		#header("x-cmd: $cmd");
		exec($cmd,$outArr,$exitCode);
		if($exitCode) {
			$o_class='important';
			$o_text=str_replace("\n","<br/>",file_get_contents($tmp));
		} elseif(''==`grep KEY $tmp`) {
			$o_class='important';
			$o_text='Falsche Kombination aus Nutzer und Passwort.';
		} else {
			`mv $tmp $outFile`;
			$o_class='success';
			$o_text='Der Schlüssel wurde wiederhergestellt und gespeichert.<br />Der Owncloud-Admin <cloud@uni-halle.de> wurde darüber informiert.';
			mail('cloud@uni-halle.de',"Neuer Key decrypted: $u_",<<<TEXT
$u_ hat seinen Schlüssel unter $outFile entschlüsseln können.

TEXT
);
		}
	}
}

?><!DOCTYPE html >
<html>
<head>
<title>MLU OC-Decryption</title>
 <meta charset="utf-8">
<link rel="stylesheet" type="text/css" href="bootstrap/dist/css/bootstrap.css">
<link rel="stylesheet" type="text/css" href="bootstrap/dist/css/bootstrap-theme.css">
<style type="text/css" media="screen">
body {
	margin: 3em auto;
	max-width: 680px;
	background: #333;
	background: rgba(255,255,255,.3);
	padding: 2em;
	border-radius: 2em;
	border: 1em solid #fff;
}
html {
	background: #94b34c;
}
.logo {
    background-image: url("//cloud.uni-halle.de/core/img/logo.svg");
    background-repeat: no-repeat;
    width: 252px;
    height: 120px;
    /*margin: 0px auto;*/
}
fieldset {
	margin-bottom: 2em;
}
</style>
<!--<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.4/jquery.min.js"></script>-->
</head>
<body>
<div class="logo"></div>
<h1>Privaten Schlüssel entschlüsseln</h1>
<form method="post" action="">
<p>Bitte verwenden Sie folgendes Formular, um Ihren privaten OwnCloud-Schlüssel zu entschlüsseln. Ihr Passwort wird nicht gespeichert.</p>
<p>Nach erfolgreicher Entschlüsselung sind die System-Administratoren in der Lage Ihnen die verschlüsselten Dateien wiederherzustellen. Sobald dieser Vorgang abgeschlossen ist, wird sich einer der Kollegen bei Ihnen melden.</p>
<p>Für Fragen und Probleme steht Ihnen unser Support unter <a href="mailto:cloud@uni-halle.de?subject=Entschlüsselung" title="Mail an den ownCloud-Support im IT-Servicezentrum">cloud@uni-halle.de</a> gern zur Verfüfung.</p>
<fieldset><legend>Login-Daten</legend>
<input type="text" name="nkz" value="<?=isset($u_)?$u_:''?>" placeholder="Nutzer-Kennzeichen"><br />
<input type="password" name="pass" placeholder="Passwort">
</fieldset>
<fieldset><legend>Ergebnis</legend>
<? if(isset($o_text)): ?><p>
<span class="label label-<?=$o_class?>"><?=$o_text?></span>
</p>
<? endif; ?>
<input type="submit" value="Entschlüsseln!">
</fieldset>
</form>
</body>
</html>
