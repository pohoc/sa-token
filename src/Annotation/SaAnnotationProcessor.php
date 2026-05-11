<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use ReflectionClass;
use SaToken\SaToken;

class SaAnnotationProcessor
{
    public static function process(string $class, string $method): void
    {
        $reflectionClass = new ReflectionClass($class);
        $reflectionMethod = $reflectionClass->getMethod($method);

        $classAttributes = $reflectionClass->getAttributes();
        $methodAttributes = $reflectionMethod->getAttributes();

        foreach ($methodAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                return;
            }
        }

        foreach ($classAttributes as $attr) {
            if ($attr->getName() === SaIgnore::class) {
                return;
            }
        }

        $allAttributes = array_merge($classAttributes, $methodAttributes);

        foreach ($allAttributes as $attr) {
            $instance = $attr->newInstance();
            $loginType = method_exists($instance, 'getLoginType') ? $instance->getLoginType() : 'login';
            $stpLogic = SaToken::getStpLogic($loginType);

            if ($instance instanceof SaCheckLogin) {
                $stpLogic->checkLogin();
            } elseif ($instance instanceof SaCheckPermission) {
                $permissions = explode(',', $instance->getValue());
                $permissions = array_map('trim', $permissions);
                if ($instance->getMode() === 'AND') {
                    $stpLogic->checkPermissionAnd($permissions);
                } else {
                    $stpLogic->checkPermissionOr($permissions);
                }
            } elseif ($instance instanceof SaCheckRole) {
                $roles = explode(',', $instance->getValue());
                $roles = array_map('trim', $roles);
                if ($instance->getMode() === 'AND') {
                    $stpLogic->checkRoleAnd($roles);
                } else {
                    $stpLogic->checkRoleOr($roles);
                }
            } elseif ($instance instanceof SaCheckSafe) {
                $stpLogic->checkSafe($instance->getService());
            } elseif ($instance instanceof SaCheckDisable) {
                $loginId = $stpLogic->getLoginId();
                if ($loginId !== null) {
                    $stpLogic->checkDisable($loginId, $instance->getService());
                }
            }
        }
    }

    public static function processCallable(callable $callable): void
    {
    }

    public static function getMethodAttributes(string $class, string $method): array
    {
        $reflectionClass = new ReflectionClass($class);
        $reflectionMethod = $reflectionClass->getMethod($method);

        $result = [];
        $classAttrs = $reflectionClass->getAttributes();
        $methodAttrs = $reflectionMethod->getAttributes();

        foreach (array_merge($classAttrs, $methodAttrs) as $attr) {
            if (str_starts_with($attr->getName(), 'SaToken\\Annotation\\')) {
                $result[] = $attr->newInstance();
            }
        }

        return $result;
    }
}
