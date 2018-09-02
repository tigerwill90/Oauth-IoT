<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/30/18
 * Time: 6:38 PM
 */

namespace Oauth\Services\Validators;

use Psr\Http\Message\ServerRequestInterface;

interface ValidatorManagerInterface
{
    /**
     * @param string $validatorAlias
     * @param Validator[] $validators
     * @return ValidatorManagerInterface
     */
    public function add(string $validatorAlias, array $validators) : ValidatorManagerInterface;

    /**
     * Validate the request for all Validator
     * @param string[] $validatorsAlias
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function validate(array $validatorsAlias, ServerRequestInterface $request) : bool;

    /**
     * Get an associative array representing all errors for all request validator
     * @return array
     */
    public function getErrorsMessages() : array;

    /**
     * Get an associative array representing all errors for a specific validator
     * @param string $validatorAlias
     * @return array
     */
    public function getErrorMessage(string $validatorAlias) : array;
}