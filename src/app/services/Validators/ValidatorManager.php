<?php
/**
 * Created by PhpStorm.
 * User: thor
 * Date: 8/29/18
 * Time: 7:57 PM
 */

namespace Oauth\Services\Validators;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Responsibility : Manage and call all request validator
 * Class ValidatorManager
 * @package Oauth\Services\Validators
 */
final class ValidatorManager implements ValidatorManagerInterface
{
    /**
     * <code>
     * $validators = [
     *      'client' => Validator(),
     *      'alias' => Validator();
     * ]
     * @var array[string][Validator]
     */
    private $validators;

    /** @var array  */
    private $errors = [];

    /**
     * Add a new Validator
     * @param string $validatorAlias
     * @param array[string][Validator] $validators
     * @return ValidatorManagerInterface
     */
    public function add(string $validatorAlias, array $validators) : ValidatorManagerInterface
    {
        $this->validators[$validatorAlias] = $validators;
        return $this;
    }

    /**
     * Validate the request for all Validator
     * @param string[] $validatorsAlias
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function validate(array $validatorsAlias, ServerRequestInterface $request) : bool
    {
        foreach ($validatorsAlias as $alias) {
            if ($this->validators[$alias] === null) {
                throw new \LogicException('No validator is register for ' . $alias . ' alias');
            }

            foreach ($this->validators[$alias] as $validator) {
                $validator->checkExist($request);
                $validator->validate($request);
                if (!empty($validator->getErrorsMessages())) {
                    foreach ($validator->getErrorsMessages() as $key => $message) {
                        $this->errors[$alias][$key] = $message;
                    }
                }
            }
        }
        return empty($this->errors);
     }

    /**
     * Get an associative array representing all errors for all request validator
     * @return array
     */
     public function getErrorsMessages() : array
     {
         return $this->errors;
     }

    /**
     * Get an associative array representing all errors for a specific validator
     * @param string $validatorAlias
     * @return array
     */
     public function getErrorMessage(string $validatorAlias) : array
     {
         return $this->errors[$validatorAlias];
     }
}