<?php


class OC_Theme {

    private $cloudName;

    function __construct() {
        $this->cloudName = "MLU-Cloud";
    }

    public function getName() {
        return $this->cloudName;
    }

}
