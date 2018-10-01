<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 29.09.2018
 * Time: 16:35
 */

namespace Oauth\Services;

interface AudienceInterface
{
    public function getAudience() : string;

    public function getScopeArray() : array;
}
