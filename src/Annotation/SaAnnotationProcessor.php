<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use ReflectionClass;
use SaToken\SaToken;
use SaToken\Security\SaSensitiveVerify;

class SaAnnotationProcessor
{
    public static function process(string $class, string $method): void
    {
        if (!class_exists($class)) {
            return;
        }
        $reflectionClass = new ReflectionClass($class);

        // 类级注解必须沿继承链合并：开发者习惯把 #[SaCheckLogin] 标在
        // BaseController 上，getAttributes() 不含父类会让继承式鉴权整体静默失效
        $classAttributes = [];
        for ($c = $reflectionClass; $c !== false; $c = $c->getParentClass()) {
            $classAttributes = array_merge($classAttributes, $c->getAttributes());
        }
        // 重写方法仍需保留基类方法上的鉴权约束；否则仅覆盖业务实现就会
        // 静默移除 #[SaCheckLogin]/权限注解。按声明类去重，避免未重写的方法重复读取。
        $methodAttributes = [];
        $seenMethodDeclarations = [];
        for ($c = $reflectionClass; $c !== false; $c = $c->getParentClass()) {
            if (!$c->hasMethod($method)) {
                continue;
            }
            $reflectedMethod = $c->getMethod($method);
            $declaration = $reflectedMethod->getDeclaringClass()->getName();
            if (isset($seenMethodDeclarations[$declaration])) {
                continue;
            }
            $seenMethodDeclarations[$declaration] = true;
            $methodAttributes = array_merge($methodAttributes, $reflectedMethod->getAttributes());
        }

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
            if (!is_string($loginType)) {
                $loginType = 'login';
            }
            $stpLogic = SaToken::getStpLogic($loginType);

            if ($instance instanceof SaCheckLogin) {
                $stpLogic->checkLogin();
            } elseif ($instance instanceof SaCheckPermission) {
                $permissions = explode(',', $instance->getValue());
                $permissions = array_map('trim', $permissions);
                if (strtoupper($instance->getMode()) === 'AND') {
                    $stpLogic->checkPermissionAnd($permissions);
                } else {
                    $stpLogic->checkPermissionOr($permissions);
                }
            } elseif ($instance instanceof SaCheckRole) {
                $roles = explode(',', $instance->getValue());
                $roles = array_map('trim', $roles);
                if (strtoupper($instance->getMode()) === 'AND') {
                    $stpLogic->checkRoleAnd($roles);
                } else {
                    $stpLogic->checkRoleOr($roles);
                }
            } elseif ($instance instanceof SaCheckSafe) {
                $service = $instance->getService();
                $loginId = $stpLogic->getLoginId();

                if ($service === 'otp' || str_starts_with($service, 'verify:')) {
                    $stpLogic->checkSafe($service);
                } elseif ($loginId !== null) {
                    if (!SaSensitiveVerify::isVerified($service, is_scalar($loginId) ? (string) $loginId : '', $loginType)) {
                        $stpLogic->checkSafe($service);
                    }
                } else {
                    $stpLogic->checkSafe($service);
                }
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

    /**
     * @return array<object>
     */
    public static function getMethodAttributes(string $class, string $method): array
    {
        if (!class_exists($class)) {
            return [];
        }
        $reflectionClass = new ReflectionClass($class);

        $result = [];
        $classAttrs = [];
        $methodAttrs = [];
        $seenMethodDeclarations = [];
        for ($c = $reflectionClass; $c !== false; $c = $c->getParentClass()) {
            $classAttrs = array_merge($classAttrs, $c->getAttributes());
            if (!$c->hasMethod($method)) {
                continue;
            }
            $reflectedMethod = $c->getMethod($method);
            $declaration = $reflectedMethod->getDeclaringClass()->getName();
            if (isset($seenMethodDeclarations[$declaration])) {
                continue;
            }
            $seenMethodDeclarations[$declaration] = true;
            $methodAttrs = array_merge($methodAttrs, $reflectedMethod->getAttributes());
        }

        foreach (array_merge($classAttrs, $methodAttrs) as $attr) {
            if (str_starts_with($attr->getName(), 'SaToken\\Annotation\\')) {
                $result[] = $attr->newInstance();
            }
        }

        return $result;
    }
}
