<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 11:21 PM
 */

namespace Oauth\Services\Validators;


use Psr\Http\Message\ServerRequestInterface;

/**
 * Responsibility : validate parameters rules
 * Class RequestValidator
 * @package Oauth\Services\Validators
 */
abstract class RequestValidator
{
    abstract public function checkParametersExist(ServerRequestInterface $request) : bool;

    abstract public function validateParameter(ServerRequestInterface  $request) : bool;
}