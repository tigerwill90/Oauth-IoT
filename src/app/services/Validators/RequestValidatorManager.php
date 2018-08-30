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
 * Class RequestValidatorManager
 * @package Oauth\Services\Validators
 */
final class RequestValidatorManager implements ValidatorManagerInterface
{
    /**
     * <code>
     * $validators = [
     *      'client' => RequestValidator(),
     *      'alias' => RequestValidator();
     * ]
     * @var array[string]RequestValidator
     */
    private $validators;

    /** @var array  */
    private $errors = [];

    /**
     * Register all RequestValidator
     * RequestValidatorManager constructor.
     * @param array $validators
     */
    public function __construct(array $validators)
    {
        $this->validators = $validators;
    }

    /**
     * Validate the request for all RequestValidator
     * @param string[] $validatorsAlias
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function validate(array $validatorsAlias, ServerRequestInterface $request) : bool
    {
        $args = $request->getParsedBody() ?? [];
        foreach ($validatorsAlias as $alias) {
            if ($this->validators[$alias] === null) {
                throw new \LogicException('No validator is register for ' . $alias . ' alias');
            }
            $this->validators[$alias]->checkParametersExist($args);
            $this->validators[$alias]->validateParameters($args);
            if (!empty($this->validators[$alias]->getErrorsMessages())) {
                $this->errors[$alias] = $this->validators[$alias]->getErrorsMessages();
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