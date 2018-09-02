<?php
/**
 * Created by PhpStorm.
 * User: Sylvain
 * Date: 02.09.2018
 * Time: 23:02
 */

namespace Oauth\Services\Validators;


use Oauth\Services\Validators\Rules\RuleValidator;
use Psr\Http\Message\ServerRequestInterface;
use Respect\Validation\Exceptions\NestedValidationException;

class AttributeValidator extends Validator
{
    /**
     * <code>
     * $attributesValidator = [
     *      'client_id' => new ClientNameRule(true),
     *      'parameter' => RuleValidator
     * ]
     * @var array[string]RuleValidator
     */
    protected $attributesValidator;

    public function __construct()
    {
    }

    /**
     * Add a new RuleValidator
     * @param string $attribute
     * @param RuleValidator $attributeRule
     * @return Validator
     */
    public function add(string $attribute, RuleValidator $attributeRule): Validator
    {
        $this->attributesValidator[$attribute] = $attributeRule;
        return $this;
    }

    public function checkExist(ServerRequestInterface $request): bool
    {
        $attributes = [];
        foreach ($this->attributesValidator as $key => $attributeValidator) {
            $attribute = $request->getAttribute($key);
            if ($attributeValidator instanceof RuleValidator) {
                if ( null === $attribute && $attributeValidator->isRequired()) {
                    $attributes[] = $key . ' attribute is required';
                }
            } else {
                throw new \InvalidArgumentException('Value of ' . $key . ' must be a child instance of RuleValidator');
            }
        }
        if (!empty($attributes)) {
            $this->requiredErrors['attributes'] = $attributes;
        }
        return empty($this->requiredErrors);
    }

    public function validate(ServerRequestInterface $request): bool
    {
        foreach ($this->attributesValidator as $key => $attributeValidator) {
            if ($attributeValidator instanceof RuleValidator) {
                $attribute = $request->getAttribute($key);
                try {
                    if (null !== $attribute) {
                        $attributeValidator->getValidator()->setName($key)->assert($attribute);
                    }
                } catch (NestedValidationException $e) {
                    if (empty($attributeValidator->getCustomMessages())) {
                        $this->validatorErrors[$key] = $e->getMessages();
                    } else {
                        $errors = [];
                        foreach (array_values($e->findMessages($attributeValidator->getCustomMessages())) as $error) {
                            if ('' !== $error) {
                                $errors[] = $error;
                            }
                        }
                        $this->validatorErrors[$key] = $errors;
                    }
                }
            } else {
                throw new \InvalidArgumentException('Key : ' . $key . ' => ' . $attributeValidator . ' must be an instance of RuleValidator');
            }
        }
        return empty($this->validatorErrors);
    }
}